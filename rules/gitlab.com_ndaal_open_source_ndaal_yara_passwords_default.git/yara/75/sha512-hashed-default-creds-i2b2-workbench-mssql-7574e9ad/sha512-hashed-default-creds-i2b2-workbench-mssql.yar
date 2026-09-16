rule sha512_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfa577a60006a87d7bf2b9c2b7817f27e9f2978925db7b0d1c7ac56295da97c61e92ced54a2f55db3be780c2cf04af86d38a51432a09a1fd02a903fd4b8c7c0e"
    $a1="e73ddf18db42a20273b827cdc5f961d449f67ad69b852b4a9117249294893dbd3bda2ab12d01ef67c9f624071901f575feb9c3bdbfe0244cdd444b2ffcf1881a"
    $a2="96c61a761cbe1cfc0e2948928d2ab7be1df673726bcc0e4d387ffc5bfffe131db7079215e8c2be77c8ed4e660ce2da8abe7b3cb5399e5a991907527b37a78624"
    $a3="0b2f936c901306956500226972cb2c758f1eda445c08a210f57cdf7e0d0fbc8fb717bd585bad148256f2979044082c0e2ca1563ba11f1a188d372e6b584017b3"
    $a4="41cf3bcfa71fc6f69dcd6e574c292372eee200eceb4354714bb5ec5c6068a6cd677f1f53596f44faccfb3e0db8176c8a559a9263a6a98d06785900a10df826ac"
    $a5="31bd9b0adf93bff0c5d564ad73179caf2b834174f687e374a8f6de81b206459ab1fceb564c4f1f0271eaff4a1d607c00168e530550ee7fa82cd71e3b1e509db5"
    $a6="8e59c9c42f5fdeaa315febff657de279d403a6e05bd6afff9baa8d549f9221e3c092cec8088d6b0cbfca45133569441b6503ed3c3a0641c74d851220b408f28a"
    $a7="d037a27439d91601bb5143bb88b259114d1e7a225e9b9c72f26ef0abf5f24dff4461e3850bf4caccafe31c8f3771b693c4add389e0ef495ac1ce56cbad5c4f58"
    $a8="3d58ab508d97ed31f5d250f4029707b8eec85652fd2740cba3a1518722eec6eb7a557cace1ab654dd69705998f4c261c422c502dea8a862ce44eacf931f8bb6d"
    $a9="10d91e298f437c0988c3a5047beac7b6ed67f3fc371aa4d2f8fca36218006ea41735fadd7a7f35824cb0a6972e6560f43700240f43a7326b6fd2b7271fd97dde"
    $a10="0c5539419a40f2e0431d26e40afc33b4f828eb18c14c70e0f5240f50bbbb1f0be5f8934fe594fca19c4992665c507be1c85cefa5b725e8acc04631723d7b816b"
    $a11="28d2f4839ebcb58804816a6c86b3ed8e5c4cf4215ea652f7b6175e1648b670c251678d0b3fa8b98f9c746c0d916484f8c1da18343a834629edcf5ddd28017d1a"
    $a12="d6fb303291e77fdf23037b5756c7b2d6f84cc2f8f2e82d732e0d5a8e50e9477377dee23659c2bdd9bbef97e5e8e9ad77beb7d22e0db83c9282b6de0ae299fc6a"
    $a13="aa03e4b7991b1ded4b6cb339d70371df5d70d9581bc6f554fd33d94a2306268fb2c210ecceb9e27fce913c607addf2a3cedeb53dc36258495ddef0cd7352a93d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}