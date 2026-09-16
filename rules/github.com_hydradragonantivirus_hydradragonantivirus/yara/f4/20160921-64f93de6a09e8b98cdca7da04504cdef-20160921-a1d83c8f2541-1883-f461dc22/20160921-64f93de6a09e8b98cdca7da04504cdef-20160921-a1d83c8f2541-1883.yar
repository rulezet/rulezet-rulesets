rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_a1d83c8f2541_1883 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash3       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash4       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash5       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1  = "00(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb" ascii
    $s2  = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"KDh\";})()," ascii
    $s3  = "unction f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){ret" ascii
    $s4  = "n f000(){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s5  = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(" ascii
    $s6  = "on f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "0(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";" ascii
    $s8  = " \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s9  = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s10 = "ion f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}