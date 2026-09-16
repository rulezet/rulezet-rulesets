rule sig_20160503_016ea44a4dc467c6e51832e269956d0c {
  meta:
    description = "datamaliciousorder - file 20160503_016ea44a4dc467c6e51832e269956d0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df1097070b6ae626796faa689c2274148700dab3cbb1309391561052ecc9ef2a"

  strings:
    $s1  = "ar x=0;x<u.length;x++)d=d.split(c+w.charAt(x)).join(String.fromCharCode(u[x]));return d.split(c+'!').join(c);})('function @un@xe" ascii
    $s2  = "eval((function(){var r=[74,82,72,75,65,70,86,88,87,89,60,85,81,90,71,80,79,66,76,94];var o=[];for(var x=0;x<r.length;x++)o[r[x]]" ascii
    $s3  = "=(1380,4003,5506,89Jt0)){switch(0J_630Jle@uyi@k@sJMe@uyi@k@s==\"@nTo@yJ\\'var q@wuiS=\"cExs\";brJ @g@jjo@ghxJM@g@jjo@ghxJHkgD@nw" ascii
    $s4  = "(p+1)-32;i=p;p++;}else if(a==96){f=94*(r.length-32+j.charCodeAt(p+1))+j.charCodeAt(p+2)-32;i=p;p+=2;}else{continue;}if(g==null)g" ascii
    $s5  = "v@u@g(\"0~)JV~Jn;if(~=Jg){~[v@u@g(\"0~}JX~JV@~uxTICSf@y~)+@h@o@p(~kIc@s@w@o~@lmva@jo=~;return ~;break};~;switch(~J^@~=(2165,4~@g" ascii
    $s6  = "Md@v@tJn;breakJP5J0z@nS=88079Jxz@nS===477JiJ vg@serp@xJnJ@\"@hi@mwJm dcyg=\"hpEu\"J8JU\"\"Jknh@w@pr@ui=@r@l@lzMz.length;while(Jw" ascii
    $s7  = "rIvc@whwg);JUTJ;@m@in)+EymJP772J0@onN=\"bgg@mDdJfonNJHp@s@y@jb@ueJgJ<true:if(1=JNJpmovyq@xJnJ<0Jl@sj@l@u@rpJnJ@1:Jc1){}J8@nj@oyD" ascii
    $s8  = "(uC@hIdDp(\"t@ix@h\")JNfE@x@ui(true)}Jx@un@xed(1,1)!=1Jdsfwhgu=61127}else {Jpx@p@h@l@x=([(9411,3009,9883,749,6854,6753,5568,2083" ascii
    $s9  = "eval((function(){var r=[74,82,72,75,65,70,86,88,87,89,60,85,81,90,71,80,79,66,76,94];var o=[];for(var x=0;x<r.length;x++)o[r[x]]" ascii
    $s10 = "d(@xxso@ik,@oxI@lJdSwrh@lv=\"@oM@tw\"JX@oxI@lJ_\"@gfbJm uCso=16974;brJ mbCIjzv=\"@ok@hx\";break}JV1JDm@n@syq(llkj@wJd@lDE@vi=par" ascii
    $s11 = "@n()~=Jn){~(Jd~(Je~){case ~Jg;~=Jw+~@u@nhu(~if(1===~){var ~)Jk~\"Jx@~=false~,1406,~){};br~)];var~;var ~:var ~\":var~=J}~)Jx~var " ascii
    $s12 = "alseJl~663,177,279,7225,0)~J%u~u==1){}Jx5==1){};~ar n@t@w@yl@y@u=fa~lseJxn@t@w@yl@y@~eak;case trueJl~\"){J<0:~(8584,8152,3651,1)" ascii
    $s13 = "(3200,5901,3)~=J\\\\var ~k@oIbJn;br~;break;case ~@wdpN@pC@i10~=e@mS@t@s@h(~TNgJO~JF@~)JS(~}function ~)+Jb(~==0Jd@~g@mpi@m@lI~\"J" ascii
    $s14 = "@rvao>(3969,4953,1676,7899,1743,710,2089,5Jofz@sT){[(4664,4567,6504,1),D@ud][(4664,4567,6504,1)]()}}}catch(hr@ms@t){}~eak;case f" ascii
    $s15 = "zluvb@tJgJ@\"CS@v@i@lJm gypC@nihJgJW;;JC00029016039JzCIM@s@v,egl@rCTu@u,false);J6J1 IEJ?J eJ:J2J\\'J7J5J3{casJ,J/J&@J.3;JC28Jy27" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}