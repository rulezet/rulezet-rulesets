rule sig_20160321_ac8e75639eb2d56ce69e872bdcc00aae {
  meta:
    description = "datamaliciousorder - file 20160321_ac8e75639eb2d56ce69e872bdcc00aae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc474b7bb6e3b35bb8abb28d54387a568e4d02d011b2a543ff5d7ba3f9d919b"

  strings:
    $s1  = "encourage(\"h\"+\"tt\"+\"p:\"+\"//\"+\"ci\"+\"de\"+(\"marketing\",\"bianca\",\"parade\",\"ac\")+\".m\"+(\"engine\",\"united\",\"" ascii
    $s2  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s3  = "    OafPpSxj = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s4  = "   zarONkb = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s5  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s6  = "encourage(\"h\"+\"tt\"+\"p:\"+\"//\"+\"ci\"+\"de\"+(\"marketing\",\"bianca\",\"parade\",\"ac\")+\".m\"+(\"engine\",\"united\",\"" ascii
    $s7  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s8  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s9  = "jvwvpWTjSqy = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s10 = "jvwvpWTjSqy = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s11 = "lLevtREfpDO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s12 = "        kOfzMdiRXtK = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s13 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s14 = "   zarONkb = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s15 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s17 = "y, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "lLevtREfpDO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s19 = "String.prototype.stint = function () { return this.substr(0, 1); };" fullword ascii
    $s20 = "        kOfzMdiRXtK = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii

  condition:
    uint16(0) == 0x4d4a and
    8 of them
}