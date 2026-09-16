rule sig_20170125_eaee3654cf887dfa312b6cb68e1ca7f8 {
  meta:
    description = "datamaliciousorder - file 20170125_eaee3654cf887dfa312b6cb68e1ca7f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e08f6d76df66af681cd017b0a0c64dfd368a48f8143f9c72f5683718ab0c7b3"

  strings:
    $s1  = "var qaxfymxa3 = xovfonjihizakvivoperiwimfabolytfoczufmabestadzacasiqboqkyblupfoxhovtycbytekefxanajonelmohidibujyqonpoqa()[iqixgi" ascii
    $s2  = "var eputip7 = ovpabiqajdelyguxsydnytopapawtyddunothobnocivbydehdydihatupyhbefhecho()[[1, /*ipq*/ , /*ux*/ , /*qky*/ ][0]] + awne" ascii
    $s3  = "return [ /*op*/ , \"C:\\\\\", /*qqo*/ , /*oc*/ ];" fullword ascii
    $s4  = "function imfovepulymqulpisbufamozucnydrynsalobxizfygetjobqadfotavgevefyky() {" fullword ascii
    $s5  = "function apidvunuzurikfycezonfejtaxybmulidynbydcoqivsemelelutdigetejlanqilapowcymoho() {" fullword ascii
    $s6  = "function hjubigykkacloxafxuglognyjjorwugacfyjwocpotzogavilgexubjohefvilyfyqgybkoqynte() {" fullword ascii
    $s7  = "function ypaxvyftoromdibwymloxuxycowlogexukwexevumtohijohkamkahvistybcirxifu() {" fullword ascii
    $s8  = "return [ /*ybz*/ , \"Get\", /*es*/ , /*qu*/ ];" fullword ascii
    $s9  = "function ujurypfyspydoptisatjometylxicevwozdyxguhgittagybjykyztoqpudovgaqoksyqvosbiskixapqy() {" fullword ascii
    $s10 = "return [ /*ifoc*/ , \"cmd\", /*gjeq*/ , /*yc*/ ];" fullword ascii
    $s11 = "function erbywivyknojcuzcymuvtabybtufdutajsymonizgobvyrumorsomrelgetqijibeven() {" fullword ascii
    $s12 = "function azzapzuqibijwivasnomfajwozizhiqrombyjrylogbyqefoqiwummixiwuvyjokpywc() {" fullword ascii
    $s13 = "var kifsycec = vluvsujpufi[uwgorquvkujvodnydbemogxetojfefavyqmubqoqucgadixyhejevequjpucxomqawfacakespasjacmalgu()[[ /*dmoxy*/ , " ascii
    $s14 = "efherixokdyxzytnijxorloktedwytofryqvoqehmoggedqogufesf()[[ /*lory*/ , /*bavh*/ , 0, /*eflyj*/ ][2]] + ypojyxjarxebzivilraviwelyt" ascii
    $s15 = "function wqiwukisrazkyvekumaftorhadwikebezrunaxukworheniqidrysesawnymuvoljaqpegnuguxcucsorv() {" fullword ascii
    $s16 = "function awnetupcomziqojynudabfybnyjowridkazojovkompanqonudovyxhuhipalilxepygychunpimupacpoba() {" fullword ascii
    $s17 = "function edamytehujifligzimunkykbumrawipqulywpuzgezwapnycedpyciwowbitezoxitaqkyjbinorl() {" fullword ascii
    $s18 = "function yxebtokvigmegmezecyfvuszizoplevuhbinroxutmuhhesegarhazubdetvanpihb() {" fullword ascii
    $s19 = "function nwobpiwnifywelxibinivmekykikevqaczykviwvyjivofnozzywuzlykxekagypekxemsa() {" fullword ascii
    $s20 = "function dupmivfykwomjulazehbinmumewfofobenosxawgohatnozyvcogdejivhohmocvuqofropide() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}