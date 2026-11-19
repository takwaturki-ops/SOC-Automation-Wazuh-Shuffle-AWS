# 🛡️ SOC Automation : Wazuh + Shuffle + AWS

> Détection automatique d'activités suspectes dans AWS, enrichissement par threat intelligence (VirusTotal) et réponse automatisée, avec notification Slack.

![Workflow Shuffle](docs/images/workflow-shuffle.png)

---

## 📌 Objectif

Réduire le temps de réponse (MTTR) d'un SOC en automatisant les tâches répétitives de l'analyste :

1. Détecter un comportement suspect dans AWS
2. Extraire les informations utiles de l'alerte
3. Vérifier la réputation de l'IP source
4. Réagir automatiquement si elle est malveillante
5. Prévenir l'équipe

## 🧭 Scénario simulé

> Création d'une clé d'accès IAM depuis une IP inconnue.

| Étape | Outil | Action |
|---|---|---|
| 1 | AWS CloudTrail | Enregistre l'événement `CreateAccessKey` |
| 2 | Amazon S3 | Stocke les logs CloudTrail |
| 3 | Wazuh | Lit le bucket, applique la règle **100501** et génère l'alerte |
| 4 | Wazuh → Shuffle | Envoie l'alerte via webhook |
| 5 | Shuffle | Extrait les champs (IP, utilisateur, action) |
| 6 | VirusTotal | Analyse la réputation de l'IP |
| 7 | Shuffle (condition) | Si l'IP est malveillante, continue |
| 8 | AWS IAM | Désactive la clé d'accès ou l'utilisateur |
| 9 | Slack | Notifie l'analyste |

## 🏗️ Architecture

```
┌──────────┐  logs   ┌────┐  lecture  ┌────────┐  webhook  ┌─────────┐
│CloudTrail│ ──────▶ │ S3 │ ────────▶ │ Wazuh  │ ────────▶ │ Shuffle │
└──────────┘         └────┘           └────────┘           └────┬────┘
                                                                │
                      ┌─────────────┬───────────────────────────┤
                      ▼             ▼                           ▼
                 VirusTotal      AWS IAM                      Slack
               (réputation IP)  (réponse)                 (notification)
```

## 🧰 Stack technique

| Composant | Rôle |
|---|---|
| **Wazuh** | SIEM/XDR : collecte, analyse, détection |
| **Shuffle** | SOAR : orchestration et automatisation |
| **AWS CloudTrail** | Journalisation des actions du compte |
| **Amazon S3** | Stockage des logs |
| **AWS IAM** | Source des événements et cible de la réponse |
| **VirusTotal** | Threat intelligence |
| **Slack** | Notification |

## ✅ Prérequis

- Une VM Ubuntu (4 Go de RAM minimum, 8 Go conseillés) pour Wazuh
- Un compte AWS (free tier)
- Un compte [Shuffle](https://shuffler.io) (cloud) ou Shuffle en Docker
- Une clé API VirusTotal (gratuite)
- Un workspace Slack avec un webhook entrant
- Notions de base : Linux, JSON, réseau

## 🚀 Mise en place

### 1. Installer Wazuh

Installation tout-en-un (manager, indexer, dashboard) sur la VM :

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Notez les identifiants affichés à la fin, puis connectez-vous au dashboard : `https://<IP_DE_LA_VM>`.
Déployez ensuite un agent sur une machine de test depuis le dashboard.

> Vérifiez la version actuelle dans la [documentation officielle Wazuh](https://documentation.wazuh.com).

### 2. Configurer AWS

1. **CloudTrail** : créer un *trail* qui enregistre les événements de gestion et les envoie vers un bucket S3.
2. **Utilisateur IAM pour Wazuh** : droits en lecture seule sur le bucket (principe du moindre privilège).
3. **Utilisateur IAM pour Shuffle** : uniquement les droits nécessaires à la réponse, par exemple :

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:UpdateAccessKey",
        "iam:ListAccessKeys",
        "iam:DeleteLoginProfile"
      ],
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/*"
    }
  ]
}
```

> ⚠️ N'attribuez jamais `AdministratorAccess` au compte utilisé par l'automatisation.

### 3. Connecter AWS à Wazuh

Dans `/var/ossec/etc/ossec.conf` sur le manager :

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>
  <bucket type="cloudtrail">
    <name>NOM_DU_BUCKET</name>
    <aws_profile>default</aws_profile>
  </bucket>
</wodle>
```

Configurez les identifiants AWS (profil `default`) pour l'utilisateur Wazuh, puis redémarrez :

```bash
sudo systemctl restart wazuh-manager
```

### 4. Créer la règle personnalisée

Dans `/var/ossec/etc/rules/local_rules.xml` :

```xml
<group name="aws,custom,">
  <rule id="100501" level="10">
    <if_group>amazon</if_group>
    <field name="aws.eventName">^CreateAccessKey$</field>
    <description>AWS IAM : création d'une clé d'accès</description>
    <mitre>
      <id>T1098.001</id>
    </mitre>
  </rule>
</group>
```

- ID `100501` : les IDs à partir de 100000 sont réservés aux règles personnalisées.
- **MITRE ATT&CK** : T1098.001 (*Account Manipulation: Additional Cloud Credentials*).
- Testez la règle avec un log réel via l'outil `wazuh-logtest` avant de l'activer.

### 5. Envoyer les alertes à Shuffle

1. Dans Shuffle, créer un workflow avec un trigger **Webhook** et copier son URL.
2. Dans `ossec.conf` :

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_XXXXXXXX</hook_url>
  <rule_id>100501</rule_id>
  <alert_format>json</alert_format>
</integration>
```

3. Redémarrer le manager.

### 6. Construire le workflow Shuffle

| Bloc | Configuration |
|---|---|
| **Webhook** | Reçoit les alertes Wazuh |
| **Extract Fields** | Récupère l'IP source, l'utilisateur IAM, l'événement |
| **Condition** | `$exec.rule` *equals* `100501` |
| **VirusTotal v3** | Requête sur l'IP source |
| **Condition** | Si le nombre de détections malveillantes dépasse le seuil défini |
| **AWS IAM** | Désactiver la clé d'accès (`UpdateAccessKey` → `Inactive`) |
| **Slack / HTTP** | Message de notification à l'analyste |

Le workflow exporté se trouve dans [`shuffle/workflow.json`](shuffle/workflow.json).

## 🧪 Tests

1. Créer une clé d'accès pour un utilisateur IAM de test.
2. Attendre l'ingestion des logs par Wazuh (jusqu'à l'intervalle configuré).
3. Vérifier l'alerte **100501** dans le dashboard Wazuh.
4. Vérifier l'exécution du workflow dans Shuffle.
5. Contrôler la réponse (clé désactivée) et la notification Slack.

| Test | Résultat attendu | Statut |
|---|---|---|
| Alerte 100501 visible dans Wazuh | ✅ | ☐ |
| Webhook reçu par Shuffle | ✅ | ☐ |
| Réputation IP retournée par VirusTotal | ✅ | ☐ |
| Clé IAM désactivée | ✅ | ☐ |
| Message Slack reçu | ✅ | ☐ |

## ⚠️ Limites et bonnes pratiques

- **Faux positifs** : une règle trop large peut désactiver des accès légitimes. Commencez par la notification seule, puis activez la réponse.
- **Quotas VirusTotal** : l'API gratuite est limitée (environ 4 requêtes par minute).
- **Secrets** : ne publiez jamais de clés AWS, clés API ou URLs de webhook sur GitHub. Utilisez des variables ou un gestionnaire de secrets.
- **Coûts AWS** : surveillez la facturation et supprimez les ressources après les tests.
- **Validation humaine** : pour un usage réel, ajoutez une étape d'approbation avant les actions destructrices.

## 📚 Compétences démontrées

- Détection SIEM et écriture de règles personnalisées
- Mapping MITRE ATT&CK
- Sécurité AWS (IAM, CloudTrail, S3, moindre privilège)
- Automatisation SOAR (workflows, webhooks, APIs, JSON)
- Threat intelligence et enrichissement d'IOC
- Réponse automatisée à incident

## 🔭 Améliorations possibles

- Ajouter d'autres règles : connexion console sans MFA, suppression de logs CloudTrail, création d'utilisateur IAM
- Créer un ticket automatiquement (TheHive, Jira)
- Ajouter une étape d'approbation humaine
- Déployer Shuffle en local avec Docker
- Construire un dashboard de suivi des alertes et du MTTR

## 📁 Structure du dépôt

```
.
├── README.md
├── docs/
│   └── images/            # Captures d'écran et schémas
├── wazuh/
│   ├── ossec.conf         # Extraits de configuration (sans secrets)
│   └── local_rules.xml    # Règle 100501
├── aws/
│   └── iam-policy.json    # Policy du compte de réponse
└── shuffle/
    └── workflow.json      # Workflow exporté
```

## 🔗 Ressources

- [Documentation Wazuh](https://documentation.wazuh.com)
- [Documentation Shuffle](https://shuffler.io/docs)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Documentation AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail)
- [API VirusTotal](https://docs.virustotal.com)

## 👤 Auteur

**Ton nom** : [LinkedIn](https://linkedin.com/in/ton-profil) · [GitHub](https://github.com/ton-profil)
