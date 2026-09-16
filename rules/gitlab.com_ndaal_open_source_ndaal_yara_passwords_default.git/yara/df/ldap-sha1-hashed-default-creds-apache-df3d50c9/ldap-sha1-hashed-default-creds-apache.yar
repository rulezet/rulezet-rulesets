rule ldap_sha1_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}RPTybnrJpO8exuh9+S4dzye6tzg="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a7="{SHA}jcpGQo0AWi9MLgOfslCWTWE5qLI="
    $a8="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a9="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a10="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a12="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}zbDnbBpphzy9zb4KFC1WwCPcnyI="
    $a15="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a16="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a17="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a18="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a19="{SHA}/Dmxjyh9i7+s6uAg9KTrMqxcHnA="
    $a20="{SHA}U2wLM5NFYWwbM8r0VEVNi4oZDWw="
    $a21="{SHA}kbGlNpWQurEABm4cg+IxehrbKnY="
    $a22="{SHA}81JJrcoRYD8yKScs/j9slaGuCP8="
    $a23="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}