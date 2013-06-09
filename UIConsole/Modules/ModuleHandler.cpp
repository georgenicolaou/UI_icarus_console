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


#include "ModuleHandler.h"
#include <string.h>
/************************************************************************/
/* Module Includes                                                      */
/************************************************************************/
#include "ModulePattern.h"
#include "ModuleInstrFinder.h"
#include "ModuleMemoryMap.h"
#include "ModuleExploitabilityAnalysis.h"
#include <stdlib.h>
#include "ModuleROPGadgetFinder.h"


PMODULE lpsModules[] = {
	&sModulePatternGenerator,
	&sModulePatternLookup,
	&sModuleInstrFinder,
	&sModuleMemoryMap,
	&sModuleExploitabilityAnalysis,
	&sModuleROPGadgetFinder
};

ModuleHandler::ModuleHandler(void)
{
}


ModuleHandler::~ModuleHandler(void)
{
}

PMODULE ModuleHandler::GetModule( char * lpszModule )
{
	int i;
	BOOL bShortType = FALSE;
	if( *(lpszModule+2) == '\0' ) bShortType = TRUE;

	for( i = 0; i < ( sizeof( lpsModules ) / sizeof( PMODULE ) ); i++ ) {
		if( bShortType ) {
			if( strcmp( lpsModules[i]->lpszModuleShortcut, lpszModule ) == 0 ) {
				return lpsModules[i];
			}
		}
		else {
			if( strcmp( lpsModules[i]->lpszModuleCommand, lpszModule ) == 0 ) {
				return lpsModules[i];
			}
		}
	}
	return NULL;
}

PMODULE * ModuleHandler::GetAllModules( int * nNumberOfModules )
{
	*nNumberOfModules = sizeof( lpsModules ) / sizeof( PMODULE );
	return (PMODULE *)lpsModules;
}

BOOL ModuleHandler::SetModuleArgument( PMODULE lpsModule, 
	char * lpszArgumentCommand, void * lpvArgument )
{
	PMODULEARGS lpsModuleArgs = lpsModule->lpsArguments;
	for( int i = 0; i < lpsModule->nNumberOfArgs; i++ ) {
		if( strcmp( lpsModuleArgs->lpArgumentCommand, lpszArgumentCommand ) == 0 ) {
			lpsModuleArgs->bSet = TRUE;
			switch( lpsModuleArgs->eVariableType ) {
			case TYPE_INT: 
				lpsModuleArgs->lpArgument = 
					(void *)atoi((char *)lpvArgument);
				break;
			case TYPE_STRING:
				lpsModuleArgs->lpArgument = lpvArgument;
				break;
			case TYPE_FLAG: break;
			}
			return TRUE;
		}
		lpsModuleArgs++;
	}
	return FALSE;
}