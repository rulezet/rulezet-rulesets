rule sig_20160321_7909b4be561ee615c191ae5aae40386b {
  meta:
    description = "datamaliciousorder - file 20160321_7909b4be561ee615c191ae5aae40386b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ae31ad9dda37d6c563f684319b62cc7ae0658f4b00f0cd8b4f45153e06f4c16"

  strings:
    $s1  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s2  = "axiom(\"h\"+\"tt\"+\"p:\"+\"//\"+\"ma\"+\"rroq\"+\"ui\"+\"net.\"+\"co\"+\"m/wp\"+\"-con\"+\"te\"+\"nt\"+\"/p\"+\"lu\"+\"gi\"+\"n" ascii
    $s3  = "    iTvmNqVhi = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s4  = "   rCCHNil = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s5  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s6  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s7  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "axiom(\"h\"+\"tt\"+\"p:\"+\"//\"+\"ma\"+\"rroq\"+\"ui\"+\"net.\"+\"co\"+\"m/wp\"+\"-con\"+\"te\"+\"nt\"+\"/p\"+\"lu\"+\"gi\"+\"n" ascii
    $s9  = "OBxGFHSI = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s10 = "var fogEY = NdctckTA[tssHSwY[bondageI - 2]](tssHSwY[bondageI - 1]);" fullword ascii
    $s11 = "OBxGFHSI = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s12 = "        NdctckTA[tssHSwY[bondageI + 1]](brass, 1, \"NLzQbuGL\" === \"RGeTgGEcPt\"); jVOCcu = \" Precompiled matchers will still " ascii
    $s13 = "yTOKCkVPM = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s14 = "        NdctckTA[tssHSwY[bondageI + 1]](brass, 1, \"NLzQbuGL\" === \"RGeTgGEcPt\"); jVOCcu = \" Precompiled matchers will still " ascii
    $s15 = "        DnVHBFWY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s16 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s17 = "encumbrance = ((\"basketball\", \"lusty\", \"FVQskw\", \"materialism\", \"pyMTxoT\") + \"MUEiitxh\").obstruction();" fullword ascii
    $s18 = "   rCCHNil = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s19 = "y ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "yTOKCkVPM = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii

  condition:
    uint16(0) == 0x6761 and
    8 of them
}