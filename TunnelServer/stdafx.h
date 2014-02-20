// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <list>

#include <libpq-fe.h>

#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>

#include <rsa/rsa.h>
#include <pem/pem.h>

#include "TunnelCommon/Crypting.h"
#include "TunnelCommon/Hash.h"
#include "TunnelCommon/Protocol.h"

#include "Software/Log.h"
#include "Software/StringService.h"

#include "NetSocket/NetCommon.h"

// TODO: reference additional headers your program requires here
