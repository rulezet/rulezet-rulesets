rule rule_GonnaCry_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'GonnaCry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GonnaCry"
        rule_category = "signature_keyword"

    strings:
                        $string1_GonnaCry_signature_keyword = /Generic\.Linux\.GonnaCryRansom/
                        $string2_GonnaCry_signature_keyword = /Linux\/Filecoder\.GonnaCry/

    condition:
        any of them
}