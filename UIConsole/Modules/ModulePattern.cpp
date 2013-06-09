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


#include "ModulePattern.h"
#include "Pattern.h"
#include "DataEncoder.h"

void ExecutePatternGen( PMODULEARGS lpModuleArgs );
void ExecutePatternLookup( PMODULEARGS lpModuleArgs );

void * lpPatternGenArgContainer[2];

MODULEARGS lpsModulePatternGeneratorArgs[] = {
	{ 
		"s", 
		"The size of the cyclic pattern", 
		TYPE_INT, 
		FALSE,
		TRUE,
		&lpPatternGenArgContainer[0] 
	},
	{ 
		"p", 
		"Custom pattern sets to generate pattern from (each set separated by a comma)",
		TYPE_STRING, 
		FALSE, 
		FALSE,
		&lpPatternGenArgContainer[1] 
	}
};

MODULE sModulePatternGenerator = {
	"Pattern Generator", 
	"Generate a cyclic pattern", 
	"pattern_generator", 
	"pg", 
	2, 
	(PMODULEARGS)&lpsModulePatternGeneratorArgs,
	&ExecutePatternGen
};

void * lpModPatLookupArgContainer[4];

MODULEARGS lpModPatLookupArgs[] = {
	{ 
		"s", 
		"The size of the cyclic pattern", 
		TYPE_INT, 
		FALSE,
		TRUE,
		&lpModPatLookupArgContainer[0] 
	},
	{ 
		"n", 
		"The niddle within the cyclic pattern to lookup", 
		TYPE_STRING, 
		FALSE,
		TRUE,
		&lpModPatLookupArgContainer[1] 
	},
	{
		"l", 
		"The architecture size in bits if hexadecimal value is given, default is 32bit", 
		TYPE_INT, 
		FALSE, 
		FALSE,
		&lpModPatLookupArgContainer[2] 
	},
	{ 
		"p", 
		"Custom pattern sets to generate pattern from (each set separated by a comma)",
		TYPE_STRING, 
		FALSE,
		FALSE,
		&lpPatternGenArgContainer[3] 
	}
};

MODULE sModulePatternLookup = {
	"Pattern Lookup",
	"Lookup the offset of a niddle within the pattern",
	"pattern_lookup",
	"pl",
	4,
	(PMODULEARGS)&lpModPatLookupArgs,
	&ExecutePatternLookup
};


BOOL SetPatternSets( Pattern * lpcPattern, char * lpSets )
{
	int nNumberOfSets = 1, i;
	char * lpTmpPtr = lpSets;
	char ** lplpszSet;
	while( *lpTmpPtr ) {
		if( *lpTmpPtr == ',' ) nNumberOfSets++;
		lpTmpPtr++;
	}
	if( ( lpcPattern->lplpszCharSet = (char **)malloc( 
		nNumberOfSets * sizeof(char *) ) ) == NULL ) {
			dprintflvl( 1, "Error allocating pattern space" );
			return FALSE;
	}
	lpcPattern->nNumberOfSets = nNumberOfSets;
	lpcPattern->lplpszCharSet[0] = lpSets;
	i = 1;
	while( *lpSets ) {
		if( *lpSets == ',' ) {
			*lpSets = '\0';
			lpcPattern->lplpszCharSet[i++] = lpSets+1;
		}
		lpSets++;
	}
	return TRUE;	
}

void ExecutePatternGen( PMODULEARGS lpModuleArgs )
{
	Pattern cPattern;
	int nPatternSize = (int)lpModuleArgs->lpArgument;
	if( (lpModuleArgs+1)->bSet == TRUE ) {
		if( SetPatternSets( &cPattern, (char *)(lpModuleArgs+1)->lpArgument ) 
			== FALSE ) {
				return;
		}
	}
	else {
		cPattern.pattern_set_default_sets();
	}
	
	printf( "%s", cPattern.pattern_create( (int)lpModuleArgs->lpArgument ) );
}

void ExecutePatternLookup( PMODULEARGS lpModuleArgs )
{
	Pattern cPattern;
	int nArchitectureSize;
	vector<int> vLocations;
	unsigned long ulHex;
	char szSearchString[5] = {0};
	
	int nPatternSize = (int)lpModuleArgs->lpArgument;
	
	char * lpNiddle = (char *)(lpModuleArgs+1)->lpArgument;
	
	if( (lpModuleArgs+2)->bSet == TRUE ) {
		nArchitectureSize = (int)(lpModuleArgs+2)->lpArgument;
	}
	else {
		nArchitectureSize = DEFAULT_ARCH_SIZE;
	}

	if( (lpModuleArgs+3)->bSet == TRUE ) {
		if( SetPatternSets( &cPattern, (char *)(lpModuleArgs+3)->lpArgument ) 
			== FALSE ) {
				return;
		}
	}
	else {
		cPattern.pattern_set_default_sets();
	}

	int nNiddleSize = strlen( lpNiddle );
	if( nNiddleSize > nArchitectureSize / 8 ) {

		dprintflvl( 3, "Got hexadecimal value niddle: %s, converting...", 
			lpNiddle );

		int nRealNiddleSize = 0;
		char * lpRealNiddle = DataEncoder::atoah( lpNiddle, &nRealNiddleSize, 
			TRUE );

		if( lpRealNiddle == NULL ) return;

		if( nRealNiddleSize != nArchitectureSize / 8 ) {
			dprintflvl( 1, "Error: Invalid Niddle size" );
		}
		vLocations = cPattern.pattern_search( nPatternSize, lpRealNiddle, 
			nRealNiddleSize );
		printf( "Offsets:\n" );
		for( int i = 0; i < (int)vLocations.size(); i++ ) {
			printf( "0x%08X ( %d )\n", vLocations[i], vLocations[i] );
		}
		free( lpRealNiddle );
	}
	else {
		vLocations = cPattern.pattern_search( nPatternSize, lpNiddle, 
			nNiddleSize );
		if( vLocations.size() != 0 ) {
			printf( "Offsets:\n" );
			for( int i = 0; i < (int)vLocations.size(); i++ ) {
				printf( "0x%08X ( %d )\n", vLocations[i], vLocations[i] );
			}
		}
	}
	
}