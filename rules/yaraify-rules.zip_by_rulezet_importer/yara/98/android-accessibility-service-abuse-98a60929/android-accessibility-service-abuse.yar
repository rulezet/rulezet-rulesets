rule Android_Accessibility_Service_Abuse
{
    meta:
        description   = "Detects Android malware abusing Accessibility Service for auto-clicking, credential theft, overlay attacks, or device takeover"
        author        = "Buga :3"
        date          = "2026-02-14"
        reference     = "https://developer.android.com/reference/android/accessibilityservice/AccessibilityService"
        tlp           = "TLP:WHITE"
        target_entity = "file"

                yarahub_author_twitter  = "@Bugamashoo"
        yarahub_reference       = "https://attack.mitre.org/techniques/T1629/001/"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_reference_md5   = "23be84b5f050cb973e6d524beb39452d"
        yarahub_uuid            = "eb8be3a0-b01d-44af-87f1-16108865aad6"
        yarahub_license         = "CC0 1.0"

    strings:
                                $zip_header    = { 50 4B 03 04 }                               $dex_magic     = { 64 65 78 0A 30 }                            $manifest      = "AndroidManifest.xml"          ascii   
                                                $acc_service   = "AccessibilityService"         ascii           $acc_bind      = "BIND_ACCESSIBILITY_SERVICE"   ascii           $acc_event     = "onAccessibilityEvent"         ascii           $acc_info      = "AccessibilityServiceInfo"     ascii           $acc_config    = "accessibility_service_config"  ascii           $acc_node      = "AccessibilityNodeInfo"        ascii           $acc_wchange   = "TYPE_WINDOW_STATE_CHANGED"    ascii           $acc_cchange   = "TYPE_WINDOW_CONTENT_CHANGED"  ascii   
                                                
                $mal_globalact = "performGlobalAction"          ascii           $mal_dispatch  = "dispatchGesture"              ascii           $mal_actclick  = "ACTION_CLICK"                 ascii           $mal_actscroll = "ACTION_SCROLL_FORWARD"        ascii           $mal_perfact   = "performAction"                ascii           $mal_settext   = "ACTION_SET_TEXT"              ascii   
                $mal_keyfilter = "FLAG_REQUEST_FILTER_KEY_EVENTS" ascii         $mal_keyevent  = "onKeyEvent"                   ascii   
                $mal_devadmin  = "BIND_DEVICE_ADMIN"            ascii           $mal_addadmin  = "android.app.action.ADD_DEVICE_ADMIN" ascii

                $mal_overlay   = "TYPE_APPLICATION_OVERLAY"     ascii           $mal_sysalert  = "SYSTEM_ALERT_WINDOW"          ascii           $mal_wmmgr     = "WindowManager$LayoutParams"   ascii   
                $mal_rcvsms    = "RECEIVE_SMS"                  ascii           $mal_readsms   = "READ_SMS"                     ascii           $mal_sendsms   = "SEND_SMS"                     ascii           $mal_smsrecv   = "SmsReceiver"                  ascii   
                $mal_getpkg    = "getInstalledPackages"         ascii           $mal_pkgadd    = "PACKAGE_ADDED"                ascii           $mal_pkgname   = "packageName"                  ascii           $mal_launcher  = "getLaunchIntentForPackage"    ascii   
                $mal_emulator  = "isEmulator"                   ascii
        $mal_rooted    = "isDeviceRooted"               ascii
        $mal_goldfish  = "goldfish"                     ascii           $mal_genymo    = "genymotion"                   ascii   
                $mal_httppost  = "POST"                         ascii
        $mal_usragent  = "User-Agent"                   ascii
        $mal_jsonobj   = "JSONObject"                   ascii
        $mal_getimei   = "getDeviceId"                  ascii           $mal_getphone  = "getLine1Number"               ascii           $mal_accounts  = "GET_ACCOUNTS"                 ascii   
                $mal_screencap = "MediaProjection"              ascii           $mal_imgread   = "ImageReader"                  ascii   
    condition:
                $zip_header at 0 and
        $dex_magic and
        $manifest and

                        2 of ($acc_*) and

                                        4 of ($mal_*)
}