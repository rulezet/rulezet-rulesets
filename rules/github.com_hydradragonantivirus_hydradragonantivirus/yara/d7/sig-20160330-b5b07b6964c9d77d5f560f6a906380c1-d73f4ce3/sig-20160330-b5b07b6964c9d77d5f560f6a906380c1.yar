rule sig_20160330_b5b07b6964c9d77d5f560f6a906380c1 {
  meta:
    description = "datamaliciousorder - file 20160330_b5b07b6964c9d77d5f560f6a906380c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "566b430ecccda14d26c1a94ccf5e6475da824c00ccab6d1a4587cb5b08e799a7"

  strings:
    $s1  = "eval(unescape([\"prevUntil&20&3D&20&28&22Msxm&22&29&2C&20key&20&3D&20&28&22ell&22&29&2C&20nonce&20&3D&20&283&29&2C&20\", \"seed&" ascii
    $s2  = "unwrap(\"ajaxSetup&5B&22op&22&20+&20timeStamp&20+&20&22n&22&5D&28getClientRects&20+&20&22E&22&20+&20eased&2C&20&22http&22&20+&20" ascii
    $s3  = "defaultValue = keys = rbrace = teardown = scriptCharset.postMap();" fullword ascii
    $s4  = "keepScripts(version, timeStamp, key);" fullword ascii
    $s5  = "unwrap(\"siblings&20&3D&20&5BselectedIndex&20+&20&22.Serv&22&20+&20clearQueue&20+&20&22LHTTP.&22&20+&20tr&2C&20&22Msxml&22&20+&2" ascii
    $s6  = "keys[parts + \"ipt\"][xml + \"ep\"](((xhrSupported / 3) - (finish & 4063)));" fullword ascii
    $s7  = "unwrap(\"hasCompare&20&3D&20rbrace&5B&22WScr&22&20+&20version&5D&5B&22Create&22&20+&20onload&20+&20&22t&22&5D&28getClass&20+&20&" ascii
    $s8  = "unwrap(\"ajaxSetup&5B&22op&22&20+&20timeStamp&20+&20&22n&22&5D&28getClientRects&20+&20&22E&22&20+&20eased&2C&20&22http&22&20+&20" ascii
    $s9  = "boolHook[\"ty\" + elementMatchers + \"e\"] = ((5 & tween) - (1 * nonce));" fullword ascii
    $s10 = "function leadingRelative(Symbol, getComputedStyle, idx) {" fullword ascii
    $s11 = "for(calculatePosition = (1 + -(matchers / 22)); calculatePosition < siblings[rcombinators + \"e\" + relative]; calculatePosition" ascii
    $s12 = "for(calculatePosition = (1 + -(matchers / 22)); calculatePosition < siblings[rcombinators + \"e\" + relative]; calculatePosition" ascii
    $s13 = "unwrap(\"insertAfter&28adown&20+&20&22//embu&22&20+&20msg&20+&20&22.my/3Z&22&20+&20before&20+&20&22s.exe&22&29&3B\".replace(/&/g" ascii
    $s14 = "hasCompare[\"Ru\" + isXMLDoc](fired);" fullword ascii
    $s15 = "unwrap(\"hasCompare&20&3D&20rbrace&5B&22WScr&22&20+&20version&5D&5B&22Create&22&20+&20onload&20+&20&22t&22&5D&28getClass&20+&20&" ascii
    $s16 = "unwrap(\"insertAfter&28adown&20+&20&22//embu&22&20+&20msg&20+&20&22.my/3Z&22&20+&20before&20+&20&22s.exe&22&29&3B\".replace(/&/g" ascii
    $s17 = "unwrap(\"ajaxSetup&20&3D&20rbrace&5B&22WScri&22&20+&20assert&5D&5B&22Crea&22&20+&20onerror&20+&20&22bje&22&20+&20dirruns&5D&28si" ascii
    $s18 = "function callbackContext(pop, contentDocument, getAttribute) {" fullword ascii
    $s19 = "return&20pipe&3B&7D&2C&20&22ipt&22&29&3BoriginalOptions&20&3\", \"D&20&28&22LHT&22&29&3B&3B\"].join(\"\")" fullword ascii
    $s20 = "boolHook[\"mo\" + seed] = ((3 | nonce) | (3 + createElement));" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}