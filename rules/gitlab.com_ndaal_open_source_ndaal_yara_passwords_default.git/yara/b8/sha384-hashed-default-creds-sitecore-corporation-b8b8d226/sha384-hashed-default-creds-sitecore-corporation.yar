rule sha384_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98a906182cdcfb1eb4eb47117600f68958e2ddd140248b47984f4bde6587b89c8215c3da895a336e94ad1aca39015c40"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    $a3="ac5e4af0bf94858024e368de990622af88b769335ff7f41e829f94e76192e894bf6bf00ea1945ea15005236ee9d38ceb"
    $a4="98a906182cdcfb1eb4eb47117600f68958e2ddd140248b47984f4bde6587b89c8215c3da895a336e94ad1aca39015c40"
    $a5="bdd81937f38ab5d0828ae02bb236a668e0761990f2378deaf63d336ee24794346e38c36cbba69fd5e4c60adaf4c7d350"
    $a6="8ac10705a78a2dcd15fa577bac70762708597a02e130d8a6192d73dababd2b14502dbeee29d0e22bc341a0c42af6a4fb"
    $a7="5beab25a43e17902abf92c2d0fccdcbbf010ff8fb64e65d804d10bd834804b7db8649eff28bcaf3f4608c727c49565eb"
    $a8="1ad0ee901a40bf4536640f4f0c8c2b9fca9f5fbac283fd6dc4d1fd7021f8ca66c69c399619921f6dec5a2d9d942bc7ac"
    $a9="b78517f162a7c5792cd74ccc019f1ba192b4ea5d6f61d659a700d11a7dff03619ef7dedb8d3ef2614990678555064ac9"
    $a10="7857a47542aca03c22c39461231a919d9904a5915937278535a41291791b96c06717638cd6b0a2e5b8a20a53ec980f57"
    $a11="9e5c714c3b67a0cbf5744ec4ba3cbe7968f79a7d700fcbc5ee5c59ca05d84ee1d766478b74cdb920c55887c2af410e0f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}