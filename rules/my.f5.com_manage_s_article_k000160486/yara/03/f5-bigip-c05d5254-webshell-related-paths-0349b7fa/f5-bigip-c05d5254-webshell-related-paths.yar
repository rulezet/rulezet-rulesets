rule F5_BIGIP_c05d5254_Webshell_Related_Paths
{
    meta:
        description = "Detects PHP renderer paths the article says may be changed in potential compromise cases"
        author = "OpenAI"
        reference = "F5 article K000160486"
        date = "2026-03-30"
        confidence = "low"
        scope = "text, logs, memory, filesystem metadata exports"

    strings:
        $w1 = "/var/sam/www/webtop/renderer/apm_css.php3" ascii
        $w2 = "/var/sam/www/webtop/renderer/full_wt.php3" ascii
        $w3 = "/var/sam/www/webtop/renderer/webtop_popup_css.php3" ascii

    condition:
        any of them
}