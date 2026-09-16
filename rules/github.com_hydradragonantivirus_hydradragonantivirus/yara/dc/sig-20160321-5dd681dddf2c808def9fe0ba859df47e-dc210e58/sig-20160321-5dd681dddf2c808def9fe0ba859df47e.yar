rule sig_20160321_5dd681dddf2c808def9fe0ba859df47e {
  meta:
    description = "datamaliciousorder - file 20160321_5dd681dddf2c808def9fe0ba859df47e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9890f01efdb2f646d0d635b89f65b35e29d430f82e6b4a50d562baa21c9c1ce"

  strings:
    $s1  = "length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rel" ascii
    $s2  = "onerous((\"scholastic\",\"considering\",\"h\")+(\"infatuation\",\"scripting\",\"ttp://tr\")+(\"chips\",\"denouement\",\"healthfu" ascii
    $s3  = "    zxgNPfx = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s4  = "   fGyWbWjybI = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens" ascii
    $s5  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s6  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s7  = "HPCMVXNth = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s8  = "HPCMVXNth = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "ctjOSWhxmi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s10 = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        fccfmEdrBe = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s12 = "onerous((\"scholastic\",\"considering\",\"h\")+(\"infatuation\",\"scripting\",\"ttp://tr\")+(\"chips\",\"denouement\",\"healthfu" ascii
    $s13 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s14 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s15 = "h ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ exp" ascii
    $s16 = "ctjOSWhxmi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s17 = "nQYaw\", (\"buildings\",\"importunity\",\"suspension\",\"h\")+\"in\"+\"se\"+\"cu\"+\"re\"+(\"flashers\",\"beats\",\"el\")+(\"pol" ascii
    $s18 = "String.prototype.anchorage = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "erify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "        GOkJaKKh[NPRodvPB[richardsI + 1]](precious, 1, \"esFPDaBljyz\" === \"vxuUGAc\"); KCSiu = \" Precompiled matchers will st" ascii

  condition:
    uint16(0) == 0x486e and
    8 of them
}