rule Mapin : android
{
    meta:
        author = "https://twitter.com/plutec_net"
        source = "https://koodous.com/"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        description = "Mapin trojan, not for droppers"
        sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

    strings:
        $a = "138675150963"         $b = "res/xml/device_admin.xml"
        $c = "Device registered: regId ="
        

    condition:
        all of them
        
}