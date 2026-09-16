rule sig_20160503_3d49ab7bd63fc3f338a2ee32ecff2db3 {
  meta:
    description = "datamaliciousorder - file 20160503_3d49ab7bd63fc3f338a2ee32ecff2db3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adaa5754f541cb8ec95be27de8b26583ee3653443bda0637b682eb5e6f8391b8"

  strings:
    $s1  = "eval((function(){var c=[80,71,94,79,85,76,90,82,89,74,88,86,66,75,60,87,81,72,70,65];var f=[];for(var z=0;z<c.length;z++)f[c[z]]" ascii
    $s2  = "iz(693,G\",\"wt@gn@yG&@g\")}else {Pv@rmd=([(7861,9409,5297,1041,163,5930,106,2474,6618,1009,0),@vScript])[(5967,3283,2014,3959,1" ascii
    $s3  = "ar z=0;z<u.length;z++)y=y.split(d+m.charAt(z)).join(String.fromCharCode(u[z]));return y.split(d+'!').join(d);})('function dc@xzz" ascii
    $s4  = "(s+1)-32;r=s;s++;}else if(j==96){t=94*(c.length-32+e.charCodeAt(s+1))+e.charCodeAt(s+2)-32;r=s;s+=2;}else{continue;}if(p==null)p" ascii
    $s5  = "o){~rcI@k=77689;break}~\"Me@voax\"}P]~P.,~,9003,3363,7342,1)~yiEr@qPI~PGtrue:~980,4379,581,3272~P24~4830,8752,1970,2)~Pqfalse:va" ascii
    $s6  = "eval((function(){var c=[80,71,94,79,85,76,90,82,89,74,88,86,66,75,60,87,81,72,70,65];var f=[];for(var z=0;z<c.length;z++)f[c[z]]" ascii
    $s7  = "ew gaun@k@n(dfeggPnE@jjDl@kxPXE@jjDl@kx=PhPv@r@z@yfx@tPo}PsT@pNr@o@rmPXT@pNr@o@rm=PYPlrp@xPo;;PZE@ygPOyIktP^r@xe@q@l@z@z=PJ42G+3" ascii
    $s8  = "q~r jjrk@q=607~[PJ~alNh@o@m(\"0~){}P]~PO@~7,1887,7077~Mj@na@mEw@s~}function ~k@lzEfgm()~)P`(~=P_+~Po;if(~)PZ@~P_);~\"PZ~)Pi(~Pt;" ascii
    $s9  = "~(3902,8362,7878,~(4Pc309:var~jr==\"@xjM\"Pm~@l@wPI~5PC9~976,7305,7162,3)~PG0:va~n@jajrPXh~zCxS=72410;break~IDp@sI@q\";break;~@h" ascii
    $s10 = ":PvMEEv@llv=\"sta@k\"P]if(5==37Pm@xg@mPo}PsbuC=\"\"Pstptl=n@gwtmf@q@v.length;while(P_@utptl-P2P0Pmt@gM@r=P%PsnNNPRPfP.P+Plqn@lsP" ascii
    $s11 = "KPgG$jePc0P{G$je==253Pm@h@l@hk=\"@nlhN\"}PG\"@rz@t\":Pv@wnSDrtaPtP8r w@svnPt;break}PZG\"POT@soo@tP^oG*=[(7945,4462,3630,1),@zcti" ascii
    $s12 = "(~=Ph}~;return ~Pe@~;Pg~;break};~Pd@~wb@yo@kl~)+say@v(~(9024,96~);@mG*~){case ~(Pm~(Pn~(7076,2~switch(~Pt){~)+fjCy(~=e@oeI(~;swi" ascii
    $s13 = ",7613,5310,3562,8683,5)PwIbsjf@ot){[(5967,3283,2014,3959,1),@q@nl@xdq@h][(5967,3283,2014,3959,1)]()}};dc@xzzxr(G\",fP},0,0)}catc" ascii
    $s14 = "tch~Ps@~){Pv~)Ps~=fP}~q@pM@s~;case ~w@wgis~;Pv~=G\"~ gai=~var ~;if(~0500~0540~\")](~:if(~0100~alse~0000~Nrfi~true~sSId~@l@w~25,6" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}