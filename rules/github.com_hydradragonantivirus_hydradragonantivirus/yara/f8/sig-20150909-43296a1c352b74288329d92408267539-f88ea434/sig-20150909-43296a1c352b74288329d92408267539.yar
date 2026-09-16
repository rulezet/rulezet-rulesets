rule sig_20150909_43296a1c352b74288329d92408267539 {
  meta:
    description = "datamaliciousorder - file 20150909_43296a1c352b74288329d92408267539.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6632cecf853f8167cc684c80fa9d0495fbf16ea15ab1a6863b3f28c7cd7b2b86"

  strings:
    $s1  = "var kStageIsReadyEvent=\"StageManager:StageIsReadyEvent\";var StageManager=Class.create({initialize:function(a,b){this.textureMa" ascii
    $s2  = "ument.fire(kStageIsReadyEvent,{})}},debugGetStageStatistics:function(){var a={numTextures:0,numPixels:0,numDegraded:0};this.debu" ascii
    $s3  = "udioTrackOffset=this.audioTrackSpacer},adjustStageToFit:function(b){if((this.showWidth!=0)&&(this.stageWidth!=0)){var d=this.sta" ascii
    $s4  = "this.handleStageSizeDidChangeEvent.bind(this))},removeTexture:function(a){a.parentNode.removeChild(a)},addHyperlink:function(b){" ascii
    $s5  = "ocument.observe(kShowSizeDidChangeEvent,this.handleShowSizeDidChangeEvent.bind(this));document.observe(kStageSizeDidChangeEvent," ascii
    $s6  = "dChangeEvent:function(a){this.showWidth=a.memo.width;this.showHeight=a.memo.height;this.adjustStageToFit(this.stage);this.adjust" ascii
    $s7  = "ne.firstChild)}this.audioTrackOffset=this.audioTrackSpacer},handleStageSizeDidChangeEvent:function(a){this.stageWidth=a.memo.wid" ascii
    $s8  = "rAllHyperlinks:function(){var a;while(this.hyperlinkPlane.childNodes.length>0){this.hyperlinkPlane.removeChild(this.hyperlinkPla" ascii
    $s9  = "gRecursivelyWalkDomFrom(this.stage,a);return a}});" fullword ascii
    $s10 = "var kStageIsReadyEvent=\"StageManager:StageIsReadyEvent\";var StageManager=Class.create({initialize:function(a,b){this.textureMa" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}