rule sig_20160329_a0cac938414577617f2560c07c8e2e85 {
  meta:
    description = "datamaliciousorder - file 20160329_a0cac938414577617f2560c07c8e2e85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7df2f05aa28247021e9349aea99e56b3a806d2f77bcc1be1374107b6336d853e"

  strings:
    $s1 = "String['' + ('mKMJCyt', 'ky51fU', 'uox3m', 'zTGIhpIpa'.charAt((-42715-93113-48104+183939))) + ('guBxKNO', 'Y2KIt22z', 'akXHgrHPo" ascii
    $s2 = "String['' + ('mKMJCyt', 'ky51fU', 'uox3m', 'zTGIhpIpa'.charAt((-42715-93113-48104+183939))) + ('guBxKNO', 'Y2KIt22z', 'akXHgrHPo" ascii
    $s3 = "', 'xAfiGUR1F', 'ie0MfKP2'.charAt((-2848+27906+50764-84348+8527)))]['lHZCwJzSsz2LS8mx1'] = function(QeiVnFBirJY6z6bv) { return t" ascii
    $s4 = "sKCadcg2judFdmb3['' + ('GtPjGcDhV', '0QF1Gi2A', 'l0aEHS9', 'Wd4nHPD', 'HEKIugG', 'w2LVANTos'.lHZCwJzSsz2LS8mx1((-40452+98546+304" ascii
    $s5 = "', 'qAa8q', 'KoeABH'.lHZCwJzSsz2LS8mx1((+47463-34484+55681-68658)))] = function() {" fullword ascii
    $s6 = "HPZkGYITyigLT5 = this;" fullword ascii
    $s7 = "} catch(QHbSu0AKB2) {" fullword ascii
    $s8 = "} catch(vaLjNoC0Pfn) {" fullword ascii

  condition:
    uint16(0) == 0x4c4f and
    all of them
}