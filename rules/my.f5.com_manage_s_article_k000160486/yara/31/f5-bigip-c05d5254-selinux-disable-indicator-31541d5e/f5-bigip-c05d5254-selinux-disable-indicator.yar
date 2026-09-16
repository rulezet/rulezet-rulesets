rule F5_BIGIP_c05d5254_SELinux_Disable_Indicator
{
    meta:
        description = "Detects audit evidence of SELinux enforcement being disabled in context described by the article"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "medium"
        scope = "audit logs, text artifacts"

    strings:
        $a1 = "received setenforce notice (enforcing=0)" ascii
        $a2 = "exe=\"/usr/lib/systemd/systemd\"" ascii
        $a3 = "sauid=0" ascii

    condition:
        $a1 and 1 of ($a2,$a3)
}