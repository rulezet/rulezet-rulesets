rule sig_20160302_d6f2f14e1aa8dcdb4f6fbfc6c5573d2d {
  meta:
    description = "datamaliciousorder - file 20160302_d6f2f14e1aa8dcdb4f6fbfc6c5573d2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b95a7f1171dfeac6894651e744ce594dc9ae148029eef15182aa6e7691ff06bf"

  strings:
    $s1 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s2 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s3 = "a[3]);var e=b(a[4]);wqL9Z1HvU2MQ15NlfIC3LK6MeI=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new ActiveXO" ascii
    $s4 = "unction b(t){return  new ActiveXObject(t)}e[a[22]](wqL9Z1HvU2MQ15NlfIC3LK6MeI,0,0)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}