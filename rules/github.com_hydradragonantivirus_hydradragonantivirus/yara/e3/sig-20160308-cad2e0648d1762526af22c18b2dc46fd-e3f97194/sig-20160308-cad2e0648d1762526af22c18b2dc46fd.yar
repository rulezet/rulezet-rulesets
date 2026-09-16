rule sig_20160308_cad2e0648d1762526af22c18b2dc46fd {
  meta:
    description = "datamaliciousorder - file 20160308_cad2e0648d1762526af22c18b2dc46fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43e87be60ea4495c48201c99ce508f9c88fb968368b960608fbf6993c9432446"

  strings:
    $s1  = "pushStack[removeClass + setGlobalEval](visibility, hasContent + createTextNode + aup + checkNonElements + getElementsByName + ch" ascii
    $s2  = "rbuggyMatches = onlyHandlers[start + gotoEnd + step + run + createButtonPseudo + proxy + errorCallback](getResponseHeader + radi" ascii
    $s3  = "rbuggyMatches = onlyHandlers[start + gotoEnd + step + run + createButtonPseudo + proxy + errorCallback](getResponseHeader + radi" ascii
    $s4  = "cur = (((15822 - pageYOffset) / (33 | time)), ((3 * origCount * 3 & (computed, 172, constructor, 30)), this));" fullword ascii
    $s5  = "oValue) + fixHooks + bindType + hidden + _queueHooks;" fullword ascii
    $s6  = "pushStack[removeClass + setGlobalEval](visibility, hasContent + createTextNode + aup + checkNonElements + getElementsByName + ch" ascii
    $s7  = "dir[forward + whitespace]();" fullword ascii
    $s8  = "cur[cssHooks + addBack][random](((87 + hasOwn) - (6235 / obj)));" fullword ascii
    $s9  = "before[Data] = ((appendTo * 3) - (Expr | 2));" fullword ascii
    $s10 = "subordinate[contentDocument + unmatched + rlocalProtocol] = (Expr | 0);" fullword ascii
    $s11 = "dir[parseFromString + ofType + specialEasing + show](rbuggyMatches, ((pdataCur) - (14 - Expr)));" fullword ascii
    $s12 = "rigCount + 0) * (argument ^ 15), ((attachEvent ^ 58), (removeProp + 90)), (isReady * 2 * cssShow, (64 * origCount + 59)), (origC" ascii
    $s13 = "while (pushStack[statusCode + firstChild + oldCache + show] < ((Math.pow(68, origCount) - 4548) / classes)) {" fullword ascii
    $s14 = "dir[funcName](pushStack[curCSSTop + fail + nodes + beforeSend + firingIndex + setFilters]);" fullword ascii
    $s15 = "random = \"Sleep\", proxy = \"ri\", setFilters = \"y\", isReady = 5;" fullword ascii
    $s16 = "forward = \"c\";" fullword ascii
    $s17 = "visibility = \"GET\", setGlobalEval = \"n\";" fullword ascii
    $s18 = "inspect = cur[close + originalSettings];" fullword ascii
    $s19 = "onlyHandlers = inspect[rclickable + hover + minWidth](close + cssNormalTransform + _$ + converters);" fullword ascii
    $s20 = "vendorPropName = siblingCheck + value;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}