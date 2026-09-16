rule sig_20170215_e64eea9d7c432055963c788b4fc34bf6 {
  meta:
    description = "datamaliciousorder - file 20170215_e64eea9d7c432055963c788b4fc34bf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de62f34bf1ef7649b0893cb10bf4e80132fe5e0caf093a148c9877b45e36df77"

  strings:
    $s1  = "var zujy = [Object, Object, Object, Object, Object, WScript][5][hjixgamifehmynbamamepxihxoduqboghafvexecsakowivazsesxifnujyhgexe" ascii
    $s2  = "var zujy = [Object, Object, Object, Object, Object, WScript][5][hjixgamifehmynbamamepxihxoduqboghafvexecsakowivazsesxifnujyhgexe" ascii
    $s3  = "function jolxesezichidupybohevilhymitodeloneddusazejuqrybapcyfkixobugnynfywmimpolalwugfuhvobaqonozylpebjifakegowsyv(uqybeh) {" fullword ascii
    $s4  = "var owytoch0 = [eval, Object][0](odawpospowqomhotaswidkanhuditdaxapwinnobkojryjidlybquzowehattefsekesqubnifadubyhabywafnemadyrev" ascii
    $s5  = "function kriqoskarfibdexkoqicvokbokfiwuvijfomevymenakmugdalbevriwyjgydelmagpanequqcituqqewdamuxyfmyzepygbivcesiqoqzexecsys(ehofy" ascii
    $s6  = "function kriqoskarfibdexkoqicvokbokfiwuvijfomevymenakmugdalbevriwyjgydelmagpanequqcituqqewdamuxyfmyzepygbivcesiqoqzexecsys(ehofy" ascii
    $s7  = "function hjixgamifehmynbamamepxihxoduqboghafvexecsakowivazsesxifnujyhgexejzulemyffoczymovmeriqoxodbanyrapgona(opnaruwk) {" fullword ascii
    $s8  = "function ygzypohugfekupipehajafadysqakunaxunackumurwydzusjyrrysinuslufaxteqzyrtesbobykycqijmubohighibrysnakh(ojroke) {" fullword ascii
    $s9  = "function dhovyzofpyskupejqatmicfavevilazyridyzezbukoprywakelrozeclulylywelwihempybomnaqibwyhudcezqywomlyxpyp(wwalse) {" fullword ascii
    $s10 = "function ghurjullypaxgosuzliwesabyseronypuvmifxikpirguguxyqofmyjxojcypofcijfywgircihwofpoxpyfojpewilexabpolequ(xyxifxa) {" fullword ascii
    $s11 = "function utologukiwlotuvtyrcicojkityztydupekcewepepkarocjuhpusmyvowwycceqyvgibovjycopikahyzagicdopydominb(akruvh) {" fullword ascii
    $s12 = "function rcyrraruwtoqpykkoxzidcutwyporgicdetvofawykulofircosulvulmizocidyhhimyfaksofkovfedtyhadylkyjfabipizaterirosu(uzytam) {" fullword ascii
    $s13 = "function vuwxuppavyjdinihazwydnugkufutwaspyzjisojqigoxlyhabuwuplukastidyjfedolwawxaswequrimypuxazaznukullusymjo(fowpah) {" fullword ascii
    $s14 = "function cybettubpugijomtepbifdazogizebvobyknahhujfojuhjyvzowokqyfehdazzyqikascecsohmekqaljuwtowdanegetekevigaw(ryzadh) {" fullword ascii
    $s15 = "function iwakuflehigpebodidgevpelhidfyjjuhbinivniqqymilwyrcaqkydemuwtufitehuronepyxxegobpikvyvsazurigsurputsygyqolog(febfanp) {" fullword ascii
    $s16 = "var rune = eccerevq;" fullword ascii
    $s17 = "function agqypcuganecurudzinzucyjoxfyjgutxaqfibonomkekjyhvanigedetidlazulablylfulgymfakfisnexfoqorcomsefpybaqozemoltoldefy(sagri" ascii
    $s18 = "function rgawuqhyxabumkyqyzahbiruzowfenfugpexfucdivuhyzhygtumejxygnuhekugpynviszariwdebfyzluwepilxelakbiniqruvreczafdovzogyfi(iw" ascii
    $s19 = "return rune;" fullword ascii
    $s20 = "function ezjedihmyqhejuqiqyjbolvudagkewgenowkevevawohirojuqevokfupylguhewijowoqazmyjgumifuzagdinsepvyzylutbinvy(wxarwuse) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}