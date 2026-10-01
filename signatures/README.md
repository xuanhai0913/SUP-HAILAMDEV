# SUP Signature Rules

## Directory Structure
```
signatures/
├── malware/
│   ├── cryptominers.yar
│   ├── credential_stealers.yar
│   ├── ransomware.yar
│   ├── backdoors.yar
│   └── trojans.yar
├── exploit/
│   ├── rce.yar
│   ├── lpe.yar
│   ├── sqli.yar
│   └── xss.yar
├── suspicious/
│   ├── obfuscation.yar
│   ├── typosquatting.yar
│   ├── dependency_confusion.yar
│   └── install_scripts.yar
├── ioc/
│   ├── known_malicious_packages.yar
│   ├── c2_infrastructure.yar
│   └── threat_actor_iocs.yar
├── ci_cd/
│   ├── pipeline_poisoning.yar
│   ├── secret_leakage.yar
│   └── unpinned_actions.yar
└── supply_chain/
    ├── repo_jacking.yar
    ├── build_compromise.yar
    └── container_poisoning.yar
```

## Rule Template

```yara
rule SupplyChain_Malicious_NPM_Install_Script
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects malicious npm install scripts with network callbacks"
        category = "suspicious"
        subcategory = "install_script"
        severity = "high"
        date = "2024-01-15"
        version = "1.0"
        reference = "https://github.com/hailamdev/sup"
        mitre_attack = "T1195.001"
        cwe = "CWE-506"

    strings:
        // Network callbacks in install scripts
        $curl_download = /curl\s+.*\|\s*(sh|bash)/
        $wget_download = /wget\s+.*\|\s*(sh|bash)/
        $fetch_eval = /fetch\(.*\)\s*\.\s*then\(.*eval/
        $axios_post = /axios\.(post|put)\(.*process\.env\./
        $fetch_exfil = /fetch\(.*['"](https?:\/\/)[^'"]*['"].*JSON\.stringify/

        // Credential access
        $npm_token = /npm[_-]?token['"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/
        $github_token = /gh[ps]_[a-zA-Z0-9]{36}/
        $aws_key = /AKIA[0-9A-Z]{16}/
        $ssh_key = /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/

        // Obfuscation indicators
        $eval_base64 = /eval\(atob\(/
        $function_constructor = /new Function\(/
        $string_from_char = /String\.fromCharCode\(/
        $hex_decode = /parseInt\(.*,\s*16\)/

        // Process execution
        $child_process = /require\(['"]child_process['"]\)/
        $exec_sync = /\.(exec|spawn|execFile)Sync\(/
        $powershell = /powershell\s+-e[nc]?\s/

        // Persistence
        $cron_install = /crontab\s+-l\s*\|\s*.*\|\s*crontab/
        $bashrc_append = />>\s*~\/\.bashrc/
        $systemd_service = /systemctl\s+(enable|start)\s/

    condition:
        uint16(0) == 0x2321 and ( // Shebang #!
            2 of ($curl_download, $wget_download, $fetch_eval, $axios_post, $fetch_exfil) or
            1 of ($npm_token, $github_token, $aws_key, $ssh_key) or
            3 of ($eval_base64, $function_constructor, $string_from_char, $hex_decode) or
            2 of ($child_process, $exec_sync, $powershell) or
            1 of ($cron_install, $bashrc_append, $systemd_service)
        )
}
```

## Cryptominer Rules

```yara
rule SupplyChain_Cryptominer_Stratum_Protocol
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects Stratum mining protocol implementation"
        category = "malware"
        subcategory = "cryptominer"
        severity = "critical"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1496"

    strings:
        $stratum_subscribe = "mining.subscribe"
        $stratum_authorize = "mining.authorize"
        $stratum_submit = "mining.submit"
        $stratum_notify = "mining.notify"
        $stratum_difficulty = "mining.set_difficulty"
        $xmrig_config = "xmrig"
        $coinhive = "coinhive"
        $cryptonight = "cryptonight"
        $randomx = "randomx"
        $stratum_tcp = /stratum\+tcp:\/\//
        $stratum_ssl = /stratum\+ssl:\/\//

    condition:
        2 of them
}
```

## Credential Stealer Rules

```yara
rule SupplyChain_Credential_Stealer_NPM_Token
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects npm token exfiltration patterns"
        category = "malware"
        subcategory = "credential_stealer"
        severity = "critical"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1555"

    strings:
        $npmrc_token = /_authToken\s*=\s*[a-zA-Z0-9_-]{20,}/
        $npm_config = /npm config set \/\/registry\.npmjs\.org\/:_authToken/
        $env_npm_token = /process\.env\.NPM_TOKEN/
        $github_pat = /ghp_[a-zA-Z0-9]{36}/
        $github_oauth = /gho_[a-zA-Z0-9]{36}/
        $pypi_token = /pypi-[a-zA-Z0-9_-]{40,}/

    condition:
        any of them
}
```

## Typosquatting Rules

```yara
rule SupplyChain_Typosquatting_Package_Name
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects potential typosquatting package names"
        category = "suspicious"
        subcategory = "typosquatting"
        severity = "medium"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1195.001"

    strings:
        // Common typosquatting patterns (examples)
        $lodash_ts = "lodashh"
        $express_ts = "expres"
        $react_ts = "ract"
        $axios_ts = "axois"
        $moment_ts = "momnet"
        $request_ts = "requset"
        $chalk_ts = "chakl"
        $uuid_ts = "uiid"

    condition:
        any of them
}
```

## Dependency Confusion Rules

```yara
rule SupplyChain_Dependency_Confusion_Scope
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects potential dependency confusion via scope hijacking"
        category = "suspicious"
        subcategory = "dependency_confusion"
        severity = "high"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1195.002"

    strings:
        $scope_at = /@[a-z0-9_-]+\//
        $internal_scope = /@(internal|private|corp|company|org|team)\//
        $unclaimed_scope = /@(admin|root|sys|dev|test|staging|prod|ci|cd)\//

    condition:
        $scope_at and (1 of ($internal_scope, $unclaimed_scope))
}
```

## CI/CD Poisoning Rules

```yara
rule SupplyChain_CI_CD_Unpinned_Action
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects unpinned GitHub Actions (mutable tags)"
        category = "ci_cd"
        subcategory = "unpinned_action"
        severity = "medium"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1195.001"

    strings:
        $uses_action = /uses:\s*([a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+)@/
        $mutable_tag = /@(main|master|latest|v[0-9]+)$/
        $no_sha = /uses:\s*[^@]+@(?!([a-f0-9]{40}|[a-f0-9]{7,}))/

    condition:
        $uses_action and ($mutable_tag or $no_sha)
}

rule SupplyChain_CI_CD_Script_Injection
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects potential script injection in CI/CD configs"
        category = "ci_cd"
        subcategory = "script_injection"
        severity = "high"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1195.001"

    strings:
        $run_interpolation = /run:\s*\|\s*\n\s*\$\{\{.*\}\}/
        $env_injection = /env:\s*\n\s*[A-Z_]+:\s*\$\{\{.*\}\}/
        $command_injection = /\$\{\{.*github\.event\..*\}\}/
        $script_tag = /<script/
        $eval_in_run = /run:.*eval\(/

    condition:
        2 of them
}

rule SupplyChain_CI_CD_Secret_Leakage
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects hardcoded secrets in CI/CD configs"
        category = "ci_cd"
        subcategory = "secret_leakage"
        severity = "critical"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1552"

    strings:
        $aws_key = /AKIA[0-9A-Z]{16}/
        $aws_secret = /[a-zA-Z0-9/+=]{40}/
        $github_token = /gh[ps]_[a-zA-Z0-9]{36}/
        $npm_token = /npm_[a-zA-Z0-9_-]{20,}/
        $slack_token = /xox[baprs]-[0-9a-zA-Z-]{10,}/
        $generic_secret = /(password|secret|key|token)\s*[:=]\s*['"][^'"]{8,}['"]/

    condition:
        any of them
}
```

## Repo Jacking Rules

```yara
rule SupplyChain_Repo_Jacking_Abandoned_Package
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects references to potentially abandoned/jacked repositories"
        category = "supply_chain"
        subcategory = "repo_jacking"
        severity = "high"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1195.002"

    strings:
        $github_com = /github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+/
        $gitlab_com = /gitlab\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+/
        $npm_registry = /registry\.npmjs\.org\/[a-zA-Z0-9_%_-]+/
        $pypi_registry = /pypi\.org\/project\/[a-zA-Z0-9_%_-]+/

    condition:
        // This rule requires external reputation checking
        // Placeholder for demonstration
        false
}
```

## Build Compromise Rules

```yara
rule SupplyChain_Build_Compromise_Timestamp_Injection
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects build timestamp injection for reproducibility breaking"
        category = "supply_chain"
        subcategory = "build_compromise"
        severity = "medium"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1553.001"

    strings:
        $date_cmd = /date\s+\+\%/
        $build_time = /BUILD_TIME|BUILD_DATE|SOURCE_DATE_EPOCH/
        $git_commit = /git\s+rev-parse\s+HEAD/
        $timestamp_var = /\$(date|DATE|TIMESTAMP)/

    condition:
        2 of them
}
```

## Container Poisoning Rules

```yara
rule SupplyChain_Container_Base_Image_Drift
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects base image drift in Dockerfiles"
        category = "supply_chain"
        subcategory = "container_poisoning"
        severity = "medium"
        date = "2024-01-15"
        version = "1.0"
        mitre_attack = "T1553.001"

    strings:
        $from_latest = /FROM\s+[^:]+:latest/
        $from_no_tag = /FROM\s+[^:\s]+$/
        $mutable_tag = /FROM\s+[^:]+:(main|master|rolling|edge)/

    condition:
        any of them
}
```

## Known Malicious Packages (Historical)

```yara
rule SupplyChain_Known_Malicious_Event_Stream
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects event-stream malicious version 3.3.6"
        category = "ioc"
        subcategory = "known_malicious"
        severity = "critical"
        date = "2018-11-26"
        version = "1.0"
        reference = "https://github.com/dominictarr/event-stream/issues/116"
        cve = "CVE-2018-19864"

    strings:
        $package_name = "event-stream"
        $malicious_version = "3.3.6"
        $flatmap_stream = "flatmap-stream"
        $bitcoin_wallet = "bitcoin"
        $copay_dash = "copay-dash"

    condition:
        $package_name and ($malicious_version or $flatmap_stream)
}

rule SupplyChain_Known_Malicious_UA_Parser_JS
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects ua-parser-js malicious versions"
        category = "ioc"
        subcategory = "known_malicious"
        severity = "critical"
        date = "2021-10-22"
        version = "1.0"
        reference = "https://github.com/faisalman/ua-parser-js/issues/426"

    strings:
        $package = "ua-parser-js"
        $versions = /0\.(7|8|9)\.[0-9]+|1\.0\.[0-9]+/
        $cryptominer = "cryptominer"

    condition:
        $package and $versions
}

rule SupplyChain_Known_Malicious_Coa_Rc
{
    meta:
        author = "SUP-HAILAMDEV"
        description = "Detects coa and rc malicious versions"
        category = "ioc"
        subcategory = "known_malicious"
        severity = "critical"
        date = "2021-11-01"
        version = "1.0"
        reference = "https://github.com/advisories/GHSA-9f85-4v5m-6x4p"

    strings:
        $coa = "coa"
        $rc = "rc"
        $versions = /2\.[0-9]+\.[0-9]+|3\.[0-9]+\.[0-9]+/
        $obfuscated = /eval\(function\(p,a,c,k,e/

    condition:
        ($coa or $rc) and $versions and $obfuscated
}
```