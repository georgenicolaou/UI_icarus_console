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

#include "UICli.h"

//#include <icarus_include.h>
#include "Modules/ModuleHandler.h"

typedef struct _cliargs {
	char * lpCommand;
	void * lpProc;
	BOOL bDieAfter;
} CLIARGS;

CLIARGS sCliArgs[] = {
	{ "h", PrintUsage, TRUE },
	{ "help", PrintUsage, TRUE },
	{ "V", PrintVersion, TRUE }
};
char * lpDisclamer = 
	"Icarus Exploitation Engine CLI\n"
	"-----------------------------------------------------------------------\n"
	"Author(s): George Nicolaou, Glafkos Charalambous\n"
	"-----------------------------------------------------------------------\n";
UICli::UICli(void)
{
}


UICli::~UICli(void)
{
}

void UICli::Serve( int argc, char * argv[] )
{
	ModuleHandler cModuleHandler;
	PMODULE lpsModule = NULL;
	PMODULEARGS lpsModuleArgs = NULL;
	char * lpszArgument;
	int i;
	if( argc < 2 ) {
		PrintUsage(); 
		return;
	}

	if( ( lpsModule = cModuleHandler.GetModule( argv[1] ) ) == NULL ) {
		printf("Unknown module specified\n");
		return;
	}

	/*
	if( ( argc - 2 ) < ( lpsModule->nNumberOfArgs * 2 ) ) {
		printf("Invalid number of arguments given for the specified module\n");
	}
	*/
	for( i = 2; i < argc; i++ ) {
		lpszArgument = argv[i];
		if( *lpszArgument == '-' ) {
			if( cModuleHandler.SetModuleArgument( lpsModule, 
				(lpszArgument+1), argv[i+1] ) == FALSE ) {
					printf( "Error Invalid Argument Given" );
					return;
			}
			i++;
			if( i > argc - 2 ) break;
		}
	}

	lpsModule->lpModuleProc( lpsModule->lpsArguments );
}

void PrintVersion()
{
	printf( "%s%s%s\n%s%s", lpDisclamer, "Icarus Version: ", ICARUSVERSION, 
		"CLI Version: ", CLIVERSION );
}

void PrintUsage()
{
	ModuleHandler cModuleHandler;
	int nNumberOfModules, i, j;
	PMODULEARGS lpsArgs;
	PMODULE * lpsModules = cModuleHandler.GetAllModules( &nNumberOfModules );
	printf( "%s%s\n", lpDisclamer, "Modules:" );
	for( i = 0; i < nNumberOfModules; i++ ) {
		printf( "\t%s, %s - %s\n\t", 
			lpsModules[i]->lpszModuleCommand, 
			lpsModules[i]->lpszModuleShortcut,
			lpsModules[i]->lpsModuleDescription	);
		lpsArgs = (PMODULEARGS)lpsModules[i]->lpsArguments;
		for( j = 0; j < lpsModules[i]->nNumberOfArgs; j++ ) {
			printf( "\t-%s: %s\n", 
				lpsArgs[j].lpArgumentCommand, 
				lpsArgs[j].lpArgumentDescription );
			if( j + 1 != lpsModules[i]->nNumberOfArgs ) {
				printf("\t");
			}
		}
		printf("\n");
	}
	printf( "Usage: icarus.exe <module> <arguments>" );
}