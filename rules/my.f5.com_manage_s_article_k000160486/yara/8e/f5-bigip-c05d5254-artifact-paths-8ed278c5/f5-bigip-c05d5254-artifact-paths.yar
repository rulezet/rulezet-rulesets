/*
  YARA rules derived from:
  "Indicators of Compromise for c05d5254"
  Intended for hunting on extracted files, logs, configs, memory dumps,
  and suspicious text artifacts from BIG-IP systems.

  These rules are not guaranteed malware signatures.
  They are IOC-focused hunting rules based on article-provided indicators.
*/

rule F5_BIGIP_c05d5254_Artifact_Paths
{
    meta:
        description = "Detects core filesystem IOC strings associated with c05d5254 on F5 BIG-IP"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "medium"
        scope = "text, logs, memory, scripts, binaries containing embedded strings"

    strings:
        $p1 = "/run/bigtlog.pipe" ascii
        $p2 = "/run/bigstart.ltm" ascii
        $p3 = "/usr/bin/umount" ascii
        $p4 = "/usr/sbin/httpd" ascii

    condition:
        2 of them
}