rule APT_Controller_Linux_REDFLARE_1
{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "79a69740-7209-5c56-ad6f-eb4d0b29beaf"
    strings:
        $1 = "/RedFlare/gorat_server"
        $2 = "RedFlare/sandals"
        $3 = "goratsvr.CommandResponse" fullword
        $4 = "goratsvr.CommandRequest" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}