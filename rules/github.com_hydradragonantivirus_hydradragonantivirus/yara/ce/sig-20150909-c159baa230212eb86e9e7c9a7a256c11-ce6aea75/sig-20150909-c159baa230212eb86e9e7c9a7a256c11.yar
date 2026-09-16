rule sig_20150909_c159baa230212eb86e9e7c9a7a256c11 {
  meta:
    description = "datamaliciousorder - file 20150909_c159baa230212eb86e9e7c9a7a256c11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa5f82edd64ad130e8bd367c53083d36866b2db3edf177b7d28e071b93b4367"

  strings:
    $s1 = "Sheet.insertRule(kKeyframesPropertyName+\" \"+a+\" {}\",0);return this.styleSheet.cssRules[0]},deleteAllAnimations:function(){wh" ascii
    $s2 = "var kKeyframeRule=window.CSSRule.WEBKIT_KEYFRAMES_RULE;var AnimationManager=Class.create({initialize:function(){var a=document.c" ascii
    $s3 = "this.styleSheet.cssRules.length>0){this.styleSheet.deleteRule(0)}this.createdAnimations=new Object()},markAnimationsCreated:func" ascii
    $s4 = "tion(a){this.createdAnimations[a]=true},animationsCreated:function(a){return this.createdAnimations[a]}});" fullword ascii
    $s5 = "=document.styleSheets[document.styleSheets.length-1];this.createdAnimations=new Object()},createAnimation:function(a){this.style" ascii
    $s6 = "var kKeyframeRule=window.CSSRule.WEBKIT_KEYFRAMES_RULE;var AnimationManager=Class.create({initialize:function(){var a=document.c" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}