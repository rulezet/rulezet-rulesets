import "pe"
rule uvvfvnnswte {
  meta:
    description = "8099 - file uvvfvnnswte.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
    date        = "2021-12-12"
    hash1       = "5551fb5702220dfc05e0811b7c91e149c21ec01e8ca210d1602e32dece1e464d"

  strings:
    $s1  = "(s#u%x0m(m#n&y*r$o&k\"j*o$y&x\"k)l#k%y!l)y#u%j0m%v0w)w.n%k0q)l.o&p/s*m-p&u/m*v.q+j%o&s%r+w%y&p%s,t&k%q&t,q&u%r'u,n%w%o%v,s%q%t%w" ascii
    $s2  = "0w(r#v%l0j(l$u\"o*u$n&p\"v*p$x&k!q)k#j%r!x)v#t,y.k%y0v)t.r%l0p)w-m&o/r*n-t&r/l)m%w+m%n&x%n+x%x&s&y,s&j%j&p,n&t(q%s,q%v%l%j,t%p%o" ascii
    $s3  = "%r0v(y#p%k0k'w&m\"p*t$m&v\"y*q$k%w!n)j#q%l!w)w.o)y.l%x0u)j.u%m0s*k-j&n/y*x-s&s0w&u%x+l%m&n%q+y%k%o&v,r&q%t&o,o'o%q%t,p%u%r%m,u%s" ascii
    $s4  = "#t%s0u(j#o%j/x$p&j\"q*w$v&y\"x*r#l%x!o)q#r%k!v(l0x)v.m%s0n)m.t%v/t*l-k&m/j*w-r%p%p&r%y+o%v&q%p+j&l%p&w,y&r%s&n)t%x%n%u,k%n%u%l,n" ascii
    $s5  = "#s+r+y+x/o#k,q$l$t%q0x$u.s*j,s0l(r&r,u0y*p%s!y-y%v'l&v%l%o-q+o%s!k-m)l!p-n!r(q(l.t)p\"o+s%k&v'j*v#w&y/n&q&w&v'm)s\"r#n/v*w/j*l\"" ascii
    $s6  = "%y&u&x!s%k%t%j%m\"p&m&k%o%n\"m%l&v%t%s\"r%q&u%y,l/o)u+p0q)y)p)q)r-y)m+x-o,u,t/u*s,n+l+k0j,t,m+q+t0w,o,x+v+y0t,y)o*k*j-q*x)j*p*o-" ascii
    $s7  = "-r#u&p.w+l#r,o%w%x%y$n%y-j,u$y(y,s,r,y$w%n-n%v-q)l%l%q%p-r!o/n+k\"r,q)q#r!s(o%l#p&s\"r.n*q&q.k*u#y+s\"j(n*o\"o)w*t)s%k#r/l,w#w'u" ascii
    $s8  = ",j/j#t(v+l#s.s%w%x%y0x$o%v%u-x,j0t$j/m+n%l$k!k\"l+t-q!p-x&y+v/l%q%s%r0n'v%w%v&m,u$w+y+r+s*s*r*q*p*o*n*m*l*k*j+y+x+w+v+u+t+s!l!w'" ascii
    $s9  = ",n0m%s$s(j0n(q#m*v0p.x0q't0w)v)x)y/m-s(y%o&m%n,w0t/l#x(r*k+p)k%p0k,v(k$w!t%j*w#x,k(o!y%y#w,j\"l&s(w%r!n*t0l0p%v#y+p+s)q%o%p$m'j0" ascii
    $s10 = "(l/j#l0u$t/n$x0y!p0n$v(k&w,p,t,t,s$w(y-u*u!o,q%m%k%j,r&m0l.s%t%t,p)u-v,o&s$j)s+w%n0l-t&q&o/w%y&t&s&r.n)x,o)t.p*w*x)u%y/m*m\"j'j#" ascii
    $s11 = "/k#u'u)x0l'y(y0t$l&v*y%s+j$t#p,t,s$w(y-u,o%m&p0p.w%j%q+w%q(q)u-y)s$v%m-o)o+n!l-t+x+y.n*x+t,y&s's*s\"j.v*t(o*y+y#t/l)v%y&o,q*u(x$" ascii
    $s12 = "&q+v.s)m/v#y%w,q,x$o/q,q,o,n,n!n0n.y0u$o%t%m)t%w-o%p%p%p%o,u)l%o-v(k%x%x%w)u\"p)o+x+x&q&p,v+u&u&t&s.m&n\"u.p*u&j,j)s0p+o*s*t#v/x" ascii
    $s13 = "+s+r/q*o*j0l,y,j,k-n+w0x$r,k.x,p,u,r0q)o%o-r%w-k(x%j$l%y!w-y)n+l$p\"q%y%x.w0o&y&l&k&j,y0x%q&n&u\"l.l*m,q)x*y+m*v#t/t$v%m&x#w/q+y" ascii
    $s14 = "+s%j/t)s+w+v(y!u,j,j,q,p&w)x*v,t,s(n(m0p$p,s,x+p%m%j)n!x-x%k,p+x%u%r!m#w)y!k&j*l\"m&y%q&l*o\"v.j*u+t&q#j&y*x*j+y#t/l)v&y/w,n#v/p" ascii
    $s15 = "/v*u'y*w(y*y(t&t-x%y%r%s0w$q(y)l(t(n(m0p$x&j'u0u&p%j%q%p+w\"n)l%t%s-w)y$t%t0o&p&l&k&j*t(y\"n/v&t&t&s&r/o%s&s&v+m#m/v#r'p)x#t*t*n" ascii
    $s16 = "'s%k/m&k&l&m0u$s(m0s*n(n0v)y(r-w,y%u,j.k,y&q'r!t-t)t%r\"k)o!o0l&t%s%r%y!x-q*u$o&w#l)r&p&s/u*p$w&o'm(r*y&k.s)x\"q'q#s*y+p/v(n#w*n" ascii
    $s17 = "\"k+m+y+x+w'y(y0t$l&v*y0t$x(w$j0m-s&j(l%k%l%m-p)l$n&p!x#o!n$n!q-q&v\"t%j%t%w!o.r*u\"s*k,q&k\"q+u%y%t\"k.u*u(p*x*j+y#t/r$v%m'x#w/" ascii
    $s18 = "(k%m+w*w(p#s'r-p+n&r0t-o%t%u$l+l&k!x-v%k%l(u%m%u%k%j%q-o)x,u-j)o+k't,j,k,l-q*j,s%l,r-t#o+t+u*v&t&j&r&y&x,o/p\"t*w*x/m+y*s#w/y$q%" ascii
    $s19 = "$t#j/v)l%w#n0j!u'k(j$y0w+v!j%r%s,j%k(n!j's%y.k%t)t%m\"q0s-n)q#y!r!s%j)l&v!s$q\"r'x0y&r*v&w!o0v)x!v\"r\"r&q*w(x!v#m+k!l#j+n%o#k#n" ascii
    $s20 = "#t%n)y/q#p(n$r%j0r)u(y-l+o0v$j's&k)t&q%k%l$s)m%w-n0l%q%p%o0v.r'x!j.t,r+j-j(j%o.s%l*k+r&l+t*p.j*w*r,j%j&w+o&y,n&u$l'n\"t(p#w/y+j)" ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "1a4ea0d6f08424c00bbeb4790cdf1ca7" and (pe.exports("GhlqallxvchxEpmvydvyzqt") and pe.exports("PyflzyhnwVkaNixwdqktzn")) or 8 of them)
}