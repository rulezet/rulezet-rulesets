rule sig_20150909_ed4bf6ebd984f5b41f7a52b749306f11 {
  meta:
    description = "datamaliciousorder - file 20150909_ed4bf6ebd984f5b41f7a52b749306f11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25bbe5eda13ae25b6f0fdf0c53dabeedb2d165a3d0ecbb836b105844b89fbbe9"

  strings:
    $x1  = "var KNStaticAssets={};KNStaticAssets[\"KNTransitionSwoosh_Shadow.png\"]=new Image();KNStaticAssets[\"KNTransitionSwoosh_Shadow.p" ascii
    $s2  = "urn a},handleScriptDidDownloadEvent:function(a){this.script=a.memo.script;this.delegate=a.memo.delegate},assetForSlide:function(" ascii
    $s3  = "up[d];if(b==null){return null}var a=this.script.slideList[b];return this.urlForTexture(c,a)},getMovieUrl:function(d,c){var b=thi" ascii
    $s4  = "st[c];var b=this.script.slides[a].assets[d];return b},getTextureUrl:function(d,c){var b=this.script.slideIndexFromSceneIndexLook" ascii
    $s5  = "ument.observe(kScriptDidDownloadEvent,(function(b){this.handleScriptDidDownloadEvent(b)}).bind(this),false)},setSceneDidLoadCall" ascii
    $s6  = "stedSlideIndex=c;b.assetRequest.state=\"KNTransitionSlide_Black.png\"}}}else{if(c<this.script.slideList.length-1){requestedSlide" ascii
    $s7  = "s.script.slideIndexFromSceneIndexLookup[d];if(b==null){return null}var a=this.script.slideList[b];return this.urlForMovie(c,a)}," ascii
    $s8  = "turesForSlide(b)}},preloadScenes:function(a){for(var c in a){var b=this.script.slideIndexFromSceneIndexLookup[c];if(b==null){con" ascii
    $s9  = "}}}return a},isScenePreloaded:function(c){var b=this.script.slideIndexFromSceneIndexLookup[c];var a=this.isSlidePreloaded(b);ret" ascii
    $s10 = "tTextureInfo:function(e,d){var c=this.script.slideIndexFromSceneIndexLookup[e];if(c==null){return null}var a=this.script.slideLi" ascii
    $s11 = "deList.indexOf(b.assetRequest.slide);if(requestedSlideIndex===-1){if(this.script.loopSlideshow){requestedSlideIndex=0}else{reque" ascii
    $s12 = "urlForAsset:function(e,c){var b=\"\";var d=this.script.slides[c].assets[e];if(d==null){return b}var a=d.url;if((a!=null)&&(a!=\"" ascii
    $s13 = ";var d=\"\";var e=this.script.slides[c].assets[g];if(e===null){return b}if(f){var a=this.script.slides[c].assets[e.movie];d=a.ur" ascii
    $s14 = "is.script.slideIndexFromSceneIndexLookup[c];if(this.delegate.loadTextureBySlideIndex){this.assetForSlide(b)}else{this.requestTex" ascii
    $s15 = "dow.local_svg=(function(i){this.handleFetchCompleted(null,i,true)}).bind(this)}var a=document.createElement(\"script\");a.setAtt" ascii
    $s16 = "bute(\"src\",c);document.head.appendChild(a)}else{var e={textureId:h,slideId:d,slideIndex:f};new Ajax.Request(c,{method:\"get\"," ascii
    $s17 = "dex=c+1}else{if(this.script.loopSlideshow){requestedSlideIndex=0}else{requestedSlideIndex=c;b.assetRequest.state=\"KNTransitionS" ascii
    $s18 = "cript.slideIndexFromSceneIndexLookup[c];if(a!=b){return}this.callSceneDidLoadCallback()},processSceneDidLoadCallback:function(a)" ascii
    $s19 = ".name;slideId=d.slide;s=this.script.slideList.indexOf(slideId)}else{t=r.textureId;slideId=r.slideId;s=r.slideIndex}var f=this.ur" ascii
    $s20 = "bject:function(d,c){var a;var b=this.script.slideIndexFromSceneIndexLookup[d];a=this.slideCache[b].textureAssets[c];return a},ge" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}