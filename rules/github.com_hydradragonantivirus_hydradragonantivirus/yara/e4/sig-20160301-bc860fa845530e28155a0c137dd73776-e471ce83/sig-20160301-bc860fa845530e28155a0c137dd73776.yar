rule sig_20160301_bc860fa845530e28155a0c137dd73776 {
  meta:
    description = "datamaliciousorder - file 20160301_bc860fa845530e28155a0c137dd73776.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e288348ef3572aba5c23c9bb4fb815fd1fd92c14c93f6c0457a01d667d242b0"

  strings:
    $x1 = "calendarViolet = firmRaid[(\"accommodation\", \"reserve\", \"memoirs\", \"ExpandEnvironmentStrings\")]((\"adaptation\", \"sympto" ascii
    $x2 = "or\", \"%TEMP%/\")) + (\"lethal\", \"record\", \"logic\", \"territoryDog\") + (\"tunnel\", \"stadium\", \"bus\", \"economy\", \"" ascii
    $s3 = "while (unisonApostrophe[(\"abort\", \"attribute\", \"brilliant\", \"readystate\")] < ((([!+[] + !+[]]) * ([!+[] + !+[]])) & (Mat" ascii
    $s4 = "while (unisonApostrophe[(\"abort\", \"attribute\", \"brilliant\", \"readystate\")] < ((([!+[] + !+[]]) * ([!+[] + !+[]])) & (Mat" ascii
    $s5 = "unisonApostrophe = duplicateImperative[(\"inspection\", \"dollar\", \"yacht\", \"encyclopedia\", function String.prototype.avenu" ascii
    $s6 = "unisonApostrophe = duplicateImperative[(\"inspection\", \"dollar\", \"yacht\", \"encyclopedia\", function String.prototype.avenu" ascii
    $s7 = "duplicateImperative = (((1000 / 25) + 61 * 3), this);" fullword ascii
    $s8 = "} catch (shuntFormula) {};" fullword ascii

  condition:
    uint16(0) == 0x7564 and
    1 of ($x*) and all of them
}