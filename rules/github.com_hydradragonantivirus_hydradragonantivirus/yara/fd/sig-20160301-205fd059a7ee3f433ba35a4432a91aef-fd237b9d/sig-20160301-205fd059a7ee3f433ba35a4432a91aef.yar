rule sig_20160301_205fd059a7ee3f433ba35a4432a91aef {
  meta:
    description = "datamaliciousorder - file 20160301_205fd059a7ee3f433ba35a4432a91aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ad4ee5d1731665ee20fbb0abe230f3b282e993b02c56b2485ed8ae587e68832"

  strings:
    $s1 = "while (plusAccommodation[(\"curs\\u0069\" + \"v\\u0065\", \"de\" + \"lt\\u0061\", \"r\\u0065a\" + \"\\u0064y\" + \"\\u0073\" + " ascii
    $s2 = "while (plusAccommodation[(\"curs\\u0069\" + \"v\\u0065\", \"de\" + \"lt\\u0061\", \"r\\u0065a\" + \"\\u0064y\" + \"\\u0073\" + " ascii
    $s3 = " collisionCensor[(\"a\" + \"\\u006et\\u0065\\u006e\" + \"n\" + \"a\", function String.prototype.confidentialPositive() {" fullword ascii
    $s4 = "mechanicRadical = (((([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1)) - 3 * 2 * 2 * 2), " ascii
    $s5 = "} catch (giganticPaste) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}