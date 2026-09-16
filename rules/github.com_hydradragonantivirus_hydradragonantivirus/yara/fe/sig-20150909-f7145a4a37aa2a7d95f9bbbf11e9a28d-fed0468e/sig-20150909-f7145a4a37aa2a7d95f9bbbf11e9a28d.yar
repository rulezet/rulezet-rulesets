rule sig_20150909_f7145a4a37aa2a7d95f9bbbf11e9a28d {
  meta:
    description = "datamaliciousorder - file 20150909_f7145a4a37aa2a7d95f9bbbf11e9a28d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6644438c4c70791a80770770e130ac78f27472558aa4a9a8ce259cff3582feb4"

  strings:
    $s1  = "var SC=SC||{},CoreDocs=CoreDocs||{},NO=false,YES=true;CoreDocs.loc=function(a,b){if(b===undefined){CoreDocs.error('\"'+a+'\" nee" ascii
    $s2  = " a comment to be picked up for loc.')}a=a.loc();a=a.replace(/@@/g,\"%@\");return a};SC.String={fmt:function(){var f=this.gsub(/%" ascii
    $s3  = "var SC=SC||{},CoreDocs=CoreDocs||{},NO=false,YES=true;CoreDocs.loc=function(a,b){if(b===undefined){CoreDocs.error('\"'+a+'\" nee" ascii
    $s4  = "b){b=String.English[this]||this}return b.fmt.apply(b,arguments)}};for(var key in SC.String){String.prototype[key]=SC.String[key]" ascii
    $s5  = ":NO,preferredLanguage:null,currentLanguage:function(){var a=(this.useAutodetectedLanguage)?(this.browserLanguage||this.preferred" ascii
    $s6  = ".slice(e,f.length))}return(c.length>1)?c.join(\"\"):c[0]},loc:function(){var a=String[String.currentLanguage()];var b=a[this];if" ascii
    $s7  = "[0-9]+)/,function(g){return(arguments[parseInt(g[1],0)-1]||\"\").toString()});var c=[];var a=-1;var e=0;var b=0;while((a=f.index" ascii
    $s8  = "izedLanguage(b);if(!String[b]){String[b]={}}Object.extend(String[b],a||{});return this}});String.English=String.English||{};Stri" ascii
    $s9  = "Language||\"en\"):(this.preferredLanguage||this.browserLanguage||\"en\");if(!this[a]){a=this.normalizedLanguage(a)}return a},nor" ascii
    $s10 = "}Object.extend(String,{browserLanguage:((navigator.language||navigator.browserLanguage).split(\"-\",1)[0]),useAutodetectedLangua" ascii
    $s11 = "zedLanguage:function(a){switch(a){case\"fr\":a=\"French\";break;case\"de\":a=\"German\";break;case\"ja\":case\"jp\":a=\"Japanese" ascii
    $s12 = "en\":a=\"English\";break;case\"es\":a=\"Spanish\";break;default:a=\"English\";break}return a},addStringsFor:function(b,a){b=Stri" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}