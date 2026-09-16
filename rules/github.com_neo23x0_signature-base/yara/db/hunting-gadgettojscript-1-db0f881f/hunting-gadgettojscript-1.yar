rule Hunting_GadgetToJScript_1
{
    meta:
        description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "76c932e0-55b3-56ef-bab6-eb6997b51ee7"
    strings:
        $s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
        $s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
        $s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"
    condition:
        any of them
}