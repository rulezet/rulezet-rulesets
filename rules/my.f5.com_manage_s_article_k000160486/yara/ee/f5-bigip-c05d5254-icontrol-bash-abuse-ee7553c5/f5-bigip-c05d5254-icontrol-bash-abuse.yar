rule F5_BIGIP_c05d5254_iControl_Bash_Abuse
{
    meta:
        description = "Detects suspicious iControl REST bash execution patterns tied to article IOC examples"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "medium"
        scope = "audit logs, text artifacts, memory"

    strings:
        $s1 = "mgmt/tm/util/bash" ascii
        $s2 = "ForwarderPassThroughWorker" ascii
        $s3 = "\"user\":\"local/f5hubblelcdadmin\"" ascii
        $s4 = "\"uri\":\"http://localhost:8100/mgmt/tm/util/bash\"" ascii
        $s5 = "\"status\":200" ascii
        $s6 = "\"from\":\"Unknown\"" ascii
        $s7 = "user=f5hubblelcdadmin" ascii
        $s8 = "cmd_data=run util bash" ascii

    condition:
        ( $s1 and 2 of ($s2,$s3,$s4,$s5,$s6,$s7,$s8) ) or
        ( $s3 and $s7 ) or
        ( $s1 and $s8 )
}