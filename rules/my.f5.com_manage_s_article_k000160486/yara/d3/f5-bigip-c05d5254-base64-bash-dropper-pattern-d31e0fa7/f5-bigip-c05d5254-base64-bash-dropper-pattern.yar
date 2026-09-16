rule F5_BIGIP_c05d5254_Base64_Bash_Dropper_Pattern
{
    meta:
        description = "Detects article-described pattern of base64 data echoed to a file and execution of /run/bigstart.ltm"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "low"
        scope = "shell history, logs, text dumps, memory"

    strings:
        $b1 = "/run/bigstart.ltm" ascii
        $b2 = "base64" ascii nocase
        $b3 = "echo " ascii
        $b4 = "run util bash" ascii
        $b5 = "/run/" ascii

    condition:
        $b1 and 2 of ($b2,$b3,$b4,$b5)
}