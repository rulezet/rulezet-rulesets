rule sig_20150909_3048aa74da6d4a0e397d95c9967f2758 {
  meta:
    description = "datamaliciousorder - file 20150909_3048aa74da6d4a0e397d95c9967f2758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57fb7c75f89b910050cd16e7fc4514715a8695d62045299455a425d1801961d3"

  strings:
    $s1 = "this.changeOrientation(a)},changeOrientation:function(a){this.orientation=a;document.fire(kOrientationChangedEvent,{orientation:" ascii
    $s2 = "function(){if(gDevice==kDeviceMobile){Event.observe(window,\"orientationchange\",this.handleDeviceOrientationChangeEvent.bind(th" ascii
    $s3 = "var kOrientationChangedEvent=\"OrientationController:OrientationChangedEvent\";var OrientationController=Class.create({initializ" ascii
    $s4 = "));this.handleDeviceOrientationChangeEvent()}this.orientation=kOrientationUnknown},handleDeviceOrientationChangeEvent:function(b" ascii
    $s5 = "){var c=window.orientation;var a=kOrientationUnknown;if((c===0)||(c===180)){a=kOrientationPortrait}else{a=kOrientationLandscape}" ascii
    $s6 = "var kOrientationChangedEvent=\"OrientationController:OrientationChangedEvent\";var OrientationController=Class.create({initializ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}