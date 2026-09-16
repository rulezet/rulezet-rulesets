rule Stop_Antivirus_Services
{
meta:
        description = "Detects attempts to stop common antivirus services"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"

    strings:
        $av_service_1 = "avp"           $av_service_2 = "McShield"          $av_service_3 = "avgnt"           $av_service_4 = "avguard"         $av_service_5 = "avastsvc"         $av_service_6 = "mbamservice"         $av_service_7 = "SBAMSvc"         $av_service_8 = "SAVService"         $cmd_stop_service = "Stop-Service"

    condition:
        $cmd_stop_service and any of ($av_service_*)
}