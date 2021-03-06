/*
Copyright (C) 2013 George Nicolaou <george[at]preaver.[dot]com>

This file is part of Exploitation Toolkit Icarus (ETI) UI Console.

Exploitation Toolkit Icarus (ETI) UI Console is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

Exploitation Toolkit Icarus (ETI) UI Console is distributed in the hope that it
will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Exploitation Toolkit Icarus (ETI) UI Console.
If not, see <http://www.gnu.org/licenses/>.
*/


#pragma once
#include <icarus_include.h>
#include "../moduledefs.h"

class ModuleHandler
{
public:
	ModuleHandler(void);
	~ModuleHandler(void);
	PMODULE GetModule( char * lpszModule );
	PMODULE * GetAllModules( int * nNumberOfModules );
	BOOL SetModuleArgument( PMODULE lpsModule, char * lpszArgumentCommand, 
		void * lpvArgument );
};

