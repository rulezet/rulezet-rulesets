rule sig_20160503_fda7bab8d3cdb29787fb54f333acfbe6 {
  meta:
    description = "datamaliciousorder - file 20160503_fda7bab8d3cdb29787fb54f333acfbe6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a303c98443a6db3b9c335f278c7d83204669f50c95954c4a5609445a943b9f4f"

  strings:
    $s1  = "eval((function(){var h=[80,81,90,89,72,85,75,87,79,71,70,88,86,66,65,76,60,94,82,74];var z=[];for(var r=0;r<h.length;r++)z[h[r]]" ascii
    $s2  = "ar r=0;r<t.length;r++)e=e.split(v+x.charAt(r)).join(String.fromCharCode(t[r]));return e.split(v+'!').join(v);})('function @sl@p@" ascii
    $s3  = "EEn@jqk\"PpDCs=@p@qi@l@vNd.lengthPpPZPdP&P$P!Ppd@gEzh@uPs;;PpP@=\"\"PpmTE=Pu@yjID@s.length;while(PZ@wmTE-(P0P.P,P*PfIlM=PiP&P$P!" ascii
    $s4  = "nbt@ri=e@h@y@zat(PeSs@l=String;Pw=Pw+Ss@l[inbt@ri](POPe@jc@ys@n=(78P`PQPIPBPE);PZPG@jc@ys@n}PUPwPFhtnn@nDe(pIl@i@q,mn@ue){sPmmn@" ascii
    $s5  = "),\"m\",cola(),\"h\",@s@zd(),@Pk(),cola(),@Px(),\"d\",qzyz()]PU@sN@mle[@n@pe]PFe@h@y@zatPYkNo@z@pt@zc=PPPiP&P$P!)+PPP\\')+PP(P0P" ascii
    $s6  = ",658,6411,0)~=Dqnf(Pu@yjID@s,~P&8~81,204,5510,4471,3~P;false:~1099,7032,8516,94~(7684,4298,353,1)~pzr@lP:~P,8~8477,8080,8048,2)~" ascii
    $s7  = "eval((function(){var h=[80,81,90,89,72,85,75,87,79,71,70,88,86,66,65,76,60,94,82,74];var z=[];for(var r=0;r<h.length;r++)z[h[r]]" ascii
    $s8  = "ctive@r@object,(9071,3101,1983,2)][1]PUsrt@gwlPFqNw(dfeggPf@pmDd@l=@g@u@zD@yM(Pexe@unaj@n=\"@kjiy@poPrxe@unaj@nP5DlnN@r@gPh}Ppji" ascii
    $s9  = "2738,8704,3~}function ~=PZ+~PQ,~,8116,8268~PZ);~\"PU~)PU~))+Pv(~Ps;if(~cmvea@u@l~tcbcdC@j(~8788,4877~P`8~@huho@tfm~};sPm~;return" ascii
    $s10 = "(m+1)-32;g=m;m++;}else if(b==96){n=94*(h.length-32+q.charCodeAt(m+1))+q.charCodeAt(m+2)-32;g=m;m+=2;}else{continue;}if(o==null)o" ascii
    $s11 = "P.,~,6695,1421,2300,~P0,~,9784,1475,3839~ak;case 1Pq~5219,2720,2349~P;0:~P8@~@m@jC@o==0){};~))+PP(~==falsePf~imS@se\":if(1=~P{l@" ascii
    $s12 = "~(Pe@~;Pl;~);switch~Pb@~@t@tak@s~h@r@rn@r~);d@l@t@~=0Pf~alseQ ~=Ps){~46,9600,~ilb@vgoE~(Pf~){case ~=Pi~)Pp~){P{~Pp@~=false~(1557" ascii
    $s13 = "@jC@o=~\"u@l@qlPrl~@qet@p=39375}~[P?~Q\\'ak;case ~if(3===1){};~=P]t@z~PF@~o@uM@lED(\"0~@o@rf@k@ziT~PI,~,5077,3625,~(3Pc\"@~eak};" ascii
    $s14 = "353,2496,9789,3369,5Ptgpv@hkDy){[(73Q)07,35Q$0,8538,5865,1),Ik@piTka][(73Q)07,35Q$0,8538,5865,1)]()}}catch(@vg@kl){}~P$6~631,358" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}