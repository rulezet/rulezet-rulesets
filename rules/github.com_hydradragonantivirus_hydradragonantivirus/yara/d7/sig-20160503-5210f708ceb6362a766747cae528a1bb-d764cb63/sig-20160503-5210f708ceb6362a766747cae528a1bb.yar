rule sig_20160503_5210f708ceb6362a766747cae528a1bb {
  meta:
    description = "datamaliciousorder - file 20160503_5210f708ceb6362a766747cae528a1bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a4af55641955dd39bae571f1444f121d12813ca559ab5336dbf65e36bf15f9"

  strings:
    $s1  = "eval((function(){var b=[66,79,85,81,94,72,90,75,65,70,60,71,76,82,88,87,74,89,80,86];var f=[];for(var q=0;q<b.length;q++)f[b[q]]" ascii
    $s2  = "ar q=0;q<z.length;q++)l=l.split(m+c.charAt(q)).join(String.fromCharCode(z[q]));return l.split(m+'!').join(m);})('function ut@t@o" ascii
    $s3  = "EBmBVB{gv@vBc;BhBs\"\"BhBx=twr.length;while(B^@qBx-(B/Ba@tf@uc@y@u=(B\"B9B#Bhf@pE@o@j@vBN62B.B-Bhlzsx@yh=aBMf@pE@o@j@vBbnnN@tS@i" ascii
    $s4  = "012032053\"BbBwBf@iiz@lg@v@zBqB636029034053016002\")]==(2402,9670,8684,200)){switch(BkBYO#BilfkMa=46583B|lfkMa===496B70Bz4===\"q" ascii
    $s5  = "(i+1)-32;a=i;i++;}else if(s==96){u=94*(b.length-32+t.charCodeAt(i+1))+t.charCodeAt(i+2)-32;a=i;i+=2;}else{continue;}if(e==null)e" ascii
    $s6  = "4B:O#Bzho@z==625){};break}BQ0}try{if(@gip@vI(1,\"@i@itI@u\",true)=BUif(gzDp(Bk,0,0,\"j@n@p\")==0){if(ut@t@o(Bk,0,340)=BUBltz@m@i" ascii
    $s7  = "(n@hkxT@x,wgs@n@g,g@nt@r@h@w){switch(0B2tmw=26584;bBD115BiIlvl@rB`if(Ilvl@r==459Bak@nm@tEgg=\"h@ouE\"};bB c@oEta=69840Bhs@r@m@x@" ascii
    $s8  = "eval((function(){var b=[66,79,85,81,94,72,90,75,65,70,60,71,76,82,88,87,74,89,80,86];var f=[];for(var q=0;q<b.length;q++)f[b[q]]" ascii
    $s9  = "jr=MtgaBuuaB[27BpBv17025\"Be @gCga=@l@ps@zmjr>(4450,9554,7801,5Bq@gCga){[(4304,211,1),znnEn][(4304,211,1)]()}}catch(hyx@tg){}~BD" ascii
    $s10 = "rue:var ~eak;case falseBi~6632,1246,2425,9308~8,6740,3429,1010,0)~B*e~eDvb==BU};bre~t@ytS@sv@xBj@x@t~@y@iS==BU};br~24Bz2==\"gTE" ascii
    $s11 = ")~k}BR~aBWk~+h@x@lqf((~ar @m@lhm@~oc@xp(twr,~=B^+(~BQ@~ak;case 1~;return ~;switch(~B]@~BZ@~=Bk){~;break};~lse;brea~xEyN@jCh~){ca" ascii
    $s12 = "((~ar l@poeDvb=\"~==trueBa~Igiit=8570;b~))BK~BC@~@x@t@y@iS=\"~}B|1==1){~}function ~reak;case ~BV;;~@zvhTSb@gy~zCdm@iIz()~loh@wg@" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}