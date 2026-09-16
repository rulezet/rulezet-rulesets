rule Virus_Hijack_Trojan_Agent_DQQO_156_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_156_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1ea7b0404efe4b7b3535bf25c529c9b44beb3349b2fa691254f1837f70a5a7d"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $x2  = "qq!r!x!/!L\"k!^!-!y\"_!`!!&\"&#&$&%&&&'&(&)&*&+&,&-&.&/&0&1&2&3&4&5&6&7&8&A&B&C&D&E&F&G&H&I&J&K&L&M&N&O&P&Q&R&S&T&U&V&W&X&''!'\"" ascii
    $s3  = "function get__nodeValue(str_json,recursion){for(var i in str_json){var a=Object.prototype.toString.call(str_json[i]);if(a==\"[ob" ascii
    $s4  = "Apparently should be %d,%d,decompressor will try reading with sampling %d,%d" fullword ascii
    $s5  = "arget[obj];if(str_obj=='string'||str_obj=='boolean'||str_obj=='undefined'){target[obj]=source[obj]}else if(str_obj=='number'){ta" ascii
    $s6  = "){for(var i=0;i<source.length;i++){target.push(source[i])}return target}else{var str_obj;for(var obj in source){str_obj=typeof t" ascii
    $s7  = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s8  = "his.getUTCDate())+'T'+f(this.getUTCHours())+':'+f(this.getUTCMinutes())+':'+f(this.getUTCSeconds())+'Z':null};String.prototype.t" ascii
    $s9  = "'){Date.prototype.toJSON=function(key){return isFinite(this.valueOf())?this.getUTCFullYear()+'-'+f(this.getUTCMonth()+1)+'-'+f(t" ascii
    $s10 = "]?GetPublicName@Contact@Util@@YA?AVCTXStringW@@K@Z" fullword ascii
    $s11 = "reading png image error" fullword ascii
    $s12 = "t Number]\"||a==\"[object Boolean]\"){str_all.push(str_json[i])}}return str_all}function get__count(c){var obj=Object.prototype." ascii
    $s13 = " ary.join('\\r\\n')}else{return''}}function get__extend(target,source){if(Object.prototype.toString.call(target)=='[object Array" ascii
    $s14 = "x86 Family %d Model %d Stepping %d" fullword ascii
    $s15 = "rget=target.concat(source)}else if(str_obj=='object'){target[obj]=get__extend(target[obj],source[obj])}}return target}}if(typeof" ascii
    $s16 = "?GetSelfUin@Contact@Util@@YAKXZ" fullword ascii
    $s17 = "ect Object]\"||a==\"[object Array]\"){if(recursion){get__nodeValue(str_json[i],recursion)}}else if(a==\"[object String]\"||a==\"" ascii
    $s18 = "LZWDecode: Corrupted LZW table" fullword ascii
    $s19 = "tring.call(c);if(obj=='[object Array]'){return c.length}else{return 0}}function get__name_All(a){var obj=Object.prototype.toStri" ascii
    $s20 = "LZW compression is not available to due to Unisys patent enforcement" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}