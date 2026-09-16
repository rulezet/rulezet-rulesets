rule pwsh_Disable_WindowsDefender 
{
    meta:
        description = "Detects scripts attempting to disable Windows Defender"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"

    strings: 
        $disable_av1 = "Disable-WindowsDefender" ascii
        $disable_av2 = "Set-MpPreference -DisableRealtimeMonitoring $true"
        $disable_av3 = "Set-MpPreference -MAPSReporting Disabled"
        $disable_av4 = "Set-MpPreference -SubmitSamplesConsent NeverSend"
        $cmd_error_action_stop = "-ErrorAction Stop"

    condition:
        $disable_av1 and (
        $disable_av2 or $disable_av3 or $disable_av4) 
        and  $cmd_error_action_stop  

}