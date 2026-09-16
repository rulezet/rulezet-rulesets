rule credit_card_regex {
    strings: $ = "RegExp(\"[0-9]{13,16}\")"
    condition: any of them
}