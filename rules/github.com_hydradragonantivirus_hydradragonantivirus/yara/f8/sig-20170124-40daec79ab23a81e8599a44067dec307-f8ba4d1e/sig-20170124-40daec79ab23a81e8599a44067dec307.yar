rule sig_20170124_40daec79ab23a81e8599a44067dec307 {
  meta:
    description = "datamaliciousorder - file 20170124_40daec79ab23a81e8599a44067dec307.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c56473edf6150f3997986baa02ea3f95671eb6d32861c146c25bede2bac2b690"

  strings:
    $s1  = "var vsogfikdef0 = xupquvzuvrehapypzyppynigywqoqlodulxatasbipidtysukiztixejajyxokzaqgopjerpokdakinvyj()[[ /*abuvfis*/ , /*pare*/ " ascii
    $s2  = "function ehmamhyhkypacbuxpofidahutvocijvukvivesuxbedelxitavifesqucogexecikajnynezpap() {" fullword ascii
    $s3  = "return [ /*ylybcus*/ , /*azevperty*/ , /*yfodw*/ , WScript, /*ufixj*/ ][3];" fullword ascii
    $s4  = "return [ /*apuft*/ , /*ilik*/ , /*ifduwxorza*/ , \"C:\\\\\", /*esanluqde*/ , /*awsanumg*/ , /*ebgaxal*/ ];" fullword ascii
    $s5  = "//if (ifpabkyd2[ipyhabxedciphyvicpuwrecizvaqawuzapkuggovisawaqdogfucicoqyjaxihojvupi()[[ /*oqzob*/ , /*nduze*/ , /*cyt*/ , 0][3]" ascii
    $s6  = "return [ /*iwduwfik*/ , /*rol*/ , /*onaxx*/ , /*xkanwoby*/ , /*alurat*/ , /*ehgodenj*/ , /*emefop*/ , \"r\"];" fullword ascii
    $s7  = "function adofsunfydybzikefunnovoxedbopvixlykgepkyjixnospyrwelakxaxogeqexovekxinatetbyfd() {" fullword ascii
    $s8  = "function rixkabjetnitfosivvelogopnyqnarwuhilxekefiqyvnocorarukytwydfafelx() {" fullword ascii
    $s9  = "return [ /*rfucotc*/ , /*yfxygorpi*/ , \"Get\", /*dxansy*/ , /*yctad*/ , /*vocjawpag*/ , /*exagf*/ ];" fullword ascii
    $s10 = "return [ /*ihundijq*/ , /*spytti*/ , \"n\", /*ycwo*/ , /*zpadqyh*/ ];" fullword ascii
    $s11 = "return [ /*ppebov*/ , \"cmd\", /*ufejz*/ , /*mejiz*/ , /*uperje*/ , /*oxufifx*/ , /*iptasu*/ ];" fullword ascii
    $s12 = "return [ /*ehtyzqyje*/ , \"ope\", /*wetbaq*/ , /*ujxodjygvy*/ , /*dxegevyz*/ , /*rripz*/ , /*logiz*/ , /*ymdyxv*/ ];" fullword ascii
    $s13 = "function tafteqposhipixwojtadsuspysurkebamneldutcuzwovjetborxuxylkuvyvoqomahkafasviwlivucodifcen() {" fullword ascii
    $s14 = "tele*/ , 4][2]] + uzmennajnojzobxyxkolazewefhaksagtelykyhejryqgopfugkekcehidryweropfovdivegiqiv()[[5, /*hxabt*/ , /*loxfeh*/ ][0" ascii
    $s15 = " 4][3]] + avagasmukqiwfighelilmipsozwupfepyhtunzyhlevrehxexdorutjoqikykotuqigumopahxihywigepxys()[[ /*lezdala*/ , 7, /*chic*/ ][" ascii
    $s16 = "function vlugsazgutvipuxutdipiplohfejxyqnixosolmuxzatokqawdybmitxozezuserelzuqwizebupnoxo() {" fullword ascii
    $s17 = "function ecetzicylybuppyjmabomurtypyxxujokizyneplosaksodevanecomsuwemwazutakky() {" fullword ascii
    $s18 = "function zycowzidudguxbuwnohavytuvlolcuvpogegbinatapdyxokevjodefiduqurzondymyrenafm() {" fullword ascii
    $s19 = "return [ /*yskys*/ , /*toqt*/ , \"run\", /*djytle*/ , /*emi*/ ];" fullword ascii
    $s20 = "function vlamkajnajjetomomucygpuzumdamofymcomywlonkuxlufsitohcyvijohgospehar() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}