rule F5_BIGIP_c05d5254_Composite_High_Signal
{
    meta:
        description = "Higher-signal composite rule requiring multiple independent indicators from the article CVE-2025-53521"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "high"
        scope = "broad hunting over logs, memory, and text artifacts"

    strings:
        $c1 = "/run/bigtlog.pipe" ascii
        $c2 = "/run/bigstart.ltm" ascii
        $c3 = "mgmt/tm/util/bash" ascii
        $c4 = "f5hubblelcdadmin" ascii
        $c5 = "received setenforce notice (enforcing=0)" ascii
        $c6 = "/var/sam/www/webtop/renderer/apm_css.php3" ascii
        $c7 = "/var/sam/www/webtop/renderer/full_wt.php3" ascii
        $c8 = "/var/sam/www/webtop/renderer/webtop_popup_css.php3" ascii

    condition:
        3 of them
}