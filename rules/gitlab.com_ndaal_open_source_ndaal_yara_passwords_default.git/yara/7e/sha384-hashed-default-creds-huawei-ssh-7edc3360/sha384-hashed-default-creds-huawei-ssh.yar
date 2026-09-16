rule sha384_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a4="793c090417a2cf388f3b608a3850b0d2a8089cb1c1e41bb7095b529867320b16ea72a1075ad5ee8b080b42470611646b"
    $a5="793c090417a2cf388f3b608a3850b0d2a8089cb1c1e41bb7095b529867320b16ea72a1075ad5ee8b080b42470611646b"
    $a6="89c276949ec33c3ceb06b06406606a8e72ccd0afd44be6fa167982445a31918ffbf223683ea695d1e8385f3e2766af14"
    $a7="a9636155bf36782c5afe93dba56bba5771148f9762dc0df829362edc53867f6518ed909f869f26ba0e994d2d53b2c6ee"
    $a8="c880b582c3edc04bc80703653a3f6ce71ba0836adea4d3b70632049b76a887b0b7df5a35fa6285e921821035b24ced15"
    $a9="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a10="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a11="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a12="b746cb73991dfd086fd2ced503a08cfda2154e9a30c1a0f28932abf7e9c48efe27d1a6aca4e6c585c4b06d65f79bdb30"
    $a13="b746cb73991dfd086fd2ced503a08cfda2154e9a30c1a0f28932abf7e9c48efe27d1a6aca4e6c585c4b06d65f79bdb30"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}