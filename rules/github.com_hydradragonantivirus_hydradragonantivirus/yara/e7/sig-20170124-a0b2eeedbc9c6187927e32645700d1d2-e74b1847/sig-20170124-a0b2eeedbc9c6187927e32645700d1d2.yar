rule sig_20170124_a0b2eeedbc9c6187927e32645700d1d2 {
  meta:
    description = "datamaliciousorder - file 20170124_a0b2eeedbc9c6187927e32645700d1d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8ea35ee70b732c0d2147e2f7d8358f07457e1b64b383f7cc421f8e7f4e47e2d"

  strings:
    $s1  = "return [\"C:\", /*xgocreku*/ , /*bdigupu*/ , /*kaboxwizb*/ , /*icfo*/ , /*ynqu*/ ];" fullword ascii
    $s2  = "return [ /*varxuhkygq*/ , /*zcexqaqviv*/ , /*ogezyku*/ , /*xex*/ , /*icosk*/ , WScript, /*elurd*/ , /*zbupate*/ ][5];" fullword ascii
    $s3  = "return [ /*tsodbeqliq*/ , /*epabajfy*/ , /*uqnihip*/ , /*watdys*/ , /*fmak*/ , \"Get\"];" fullword ascii
    $s4  = "return [ /*ifqylzybs*/ , /*bvekzuvqe*/ , /*pynbexsipm*/ , /*igetqumn*/ , \"e8\"];" fullword ascii
    $s5  = "function fridzuhumdyxbibgalogavzyjnojyctasotathusixitijsibtywrolefexodhegozajugsujoxse() {" fullword ascii
    $s6  = "function ongyxobuzoxinalcoclavgetifinkokjusywrehcycsozylevefxigcyxsuzsysomalavmusp() {" fullword ascii
    $s7  = "return [ /*johpubi*/ , \"s\\\\\", /*xymdeh*/ , /*fotysj*/ , /*avywkaqco*/ , /*qzyryj*/ , /*espostulry*/ ];" fullword ascii
    $s8  = "function svalzizybitovbovanesiqfodxuzsisynijmihivungelunsorircipyxiloxmuzx() {" fullword ascii
    $s9  = "function jqelcywigbazmufaparpajozwezevqeriqwobratsevilbojamudatilejjexafiqziqsyzmepik() {" fullword ascii
    $s10 = "return [ /*issudum*/ , /*ojsekadmu*/ , /*tihu*/ , \"cmd\", /*kguratu*/ , /*imvaxohj*/ ];" fullword ascii
    $s11 = "function ihoflewuxovagzalluwezryxodygupuspyvvugeragafisorymagyvringa() {" fullword ascii
    $s12 = "function ogpydanevloguhiljyhbefvolinnatyfneheswevevizejrigygocujgaztotedakdalupwidbavu() {" fullword ascii
    $s13 = "function hkybuwvufjinanlymdywpukbynydutpazazwetawcurlilexecavozoqovaxybqubcukaqisukabirtuvquqjo() {" fullword ascii
    $s14 = "tunk*/ , 2, /*mmamjy*/ ][3]] + uknihxiricexugridlotmahbenvagerowuqejolzisynesypbagfohlocukhogcyczodetywu()[[0, /*otivdi*/ , /*ip" ascii
    $s15 = "function curejsedlekzetuftawmakodomagejugcomihohhykgarhisnevqejnoxdikarilseqwyroxpivz() {" fullword ascii
    $s16 = "function cmoqwylquxrugryvxabodebinzivympogimadydarozujohwetaksydfalepetaczijypysrobiqis() {" fullword ascii
    $s17 = "function usexefuserminacuqohjubagimogymizwaweqjeziszofvejypsufiboxup() {" fullword ascii
    $s18 = "function ohtunapgirohhizsyxdotelyfossoxyqowtetboxuxobyjawylfunikgozluwriqvitvywvugximrixcomh() {" fullword ascii
    $s19 = "return [ /*bbowq*/ , /*mcyn*/ , /*azvabd*/ , /*vovrunupj*/ , \"e\"];" fullword ascii
    $s20 = "function adbuvajzeqohujudynuqaryrunyvvemvyqhasexuzkybzasnemciwxoqfapvyspuzsurvuj() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}