/*!
 *
 * Password Checker v1.2
 *
 * Copyright 2015 Leon Cilliers (phaze-phusion.co.za)
 * Released under the terms of the GNU General Public License v3
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Project site: http://phaze-phusion.co.za/password-checker
 * Github site: https://github.com/phaze-phusion/password-checker
 *
 * Contains excerpt from Matthijs van Henten (https://github.com/mvhenten)
 *    https://github.com/mvhenten/string-entropy/blob/master/index.js
 *    Release under the MIT license 2014
 *
 */

/*!
 * Date: 2015-07-27
 *
 * Change-log
 *
 * v1.2    Added entropy as a nice to know front-end feature
 *         Entropy doesn't affect the score, for the reason see the following paper:
 *           http://reusablesec.blogspot.com/2010/10/new-paper-on-password-security-metrics.html)
 *
 * v1.1    Fixed warning break points for consecutive characters
 *
 * v1.0    First release
 *
 * TODO: Split symbols between keyboard symbols and other unicode characters
 * TODO: Add checkbox for Question: Does the password contain your username, whether obfuscated or not?
 * TODO: Add checkbox for Question: Does the password contain any personal identifiable information?
 * TODO: Add checkbox for Question: Does the password contain a dictionary word?
 *
 */

/**
 * Documentation backing most ideas behind this password checker:
 *
 * - Reusable Security: New Paper on Password Security Metrics
 *     http://reusablesec.blogspot.com/2010/10/new-paper-on-password-security-metrics.html
 *
 * - Short complex password, or long dictionary passphrase?
 *     http://security.stackexchange.com/questions/6095/xkcd-936-short-complex-password-or-long-dictionary-passphrase/6096#6096
 *
 */

/**
 * Primary DOM Object
 * @alias window.pwdchk
 * @type {Object}
 */
var pwdchk = {};

/**
 * Namespace functions
 * @param {string} namespaceString
 * @param {function} functionImplementation
 * @returns {window|function|object}
 */
pwdchk.namespace = function (namespaceString,functionImplementation) {
	var parts = namespaceString.split('.'),
		parent = window,
		currentPart = '';

	for(var i = 0,length = parts.length; i < length; i++) {
		currentPart = parts[i];
		parent[currentPart] = parent[currentPart] || {};
		if((i+1)==length){
			parent[currentPart] = functionImplementation;
		}else{
			parent = parent[currentPart];
		}
	}
	return parent;
};

(function() {

	"use strict";

	var ScoreCard = function() {
		var	_scorecard = this;

		/**
		 * Password string
		 * @type {string}
		 */
		_scorecard.STR = '';

		/**
		 * Password character array
		 * @type {Array}
		 */
		_scorecard.ARR = [];

		/**
		 * Password length
		 * @type {Number}
		 */
		_scorecard.LEN = 0;

		/**
		 * Total score
		 * @type {Number}
		 */
		_scorecard.TOT = 0;

		/**
		 * Password Entropy
		 * @type {Number}
		 */
		_scorecard.ENT = 0;

		/**
		 * Password complexity grade
		 * @type {String}
		 */
		_scorecard.GRA = '';

		/**
		 * Password score adjusted to percentage
		 * @type {Number}
		 */
		_scorecard.ADJ = 0;

		/**
		 * Factor by which to adjusted score
		 * @type {Number}
		 */
		_scorecard.FAC = 0.9;

		var adjustScore = function(){
			_scorecard.ADJ = _scorecard.TOT * _scorecard.FAC;

			if (_scorecard.ADJ < 0) {
				_scorecard.ADJ = 0;
			}
			else if (_scorecard.ADJ > 100) {
				_scorecard.ADJ = 100;
			}
			else {
				_scorecard.ADJ = Math.round(_scorecard.ADJ);
			}
		};

		/**
		 * The first function fired when a password character is inserted
		 *
		 * @param {String} passwordString The input string
		 * @param {Boolean} reset Flag to reset total and bypassing the determination functions
		 */
		_scorecard.setPassword = function(passwordString, reset){
			reset = (typeof reset !== 'undefined') ? reset : false;
			_scorecard.STR = passwordString;
			_scorecard.ARR = passwordString.split('');
			_scorecard.LEN = _scorecard.ARR.length;
			_scorecard.TOT = 0;

			if(!reset)
				pwdchk.looper.determineThings();
		};

		/**
		 * Call this function at the end of the last counting calculation
		 *   normally pwdchk.basic.requirements.score()
		 */
		_scorecard.lastCall = function(){

			// Adjust the score
			adjustScore();

			// Determine the grade
			pwdchk.grade.determineGrade();
		};

		_scorecard.tallyScore = function(scoreToAdd){
			_scorecard.TOT += scoreToAdd;
		};

	};

	pwdchk.namespace('PWD', new ScoreCard() );

	// ------------------------------------------------------------------------------------------------

	var DeterminerOfThings = function() {

		var onlyLetters = false;
		var onlyNumeric = false;
		var onlySymbols = false;

		var checkOnlys = function(){
			var onlyLettersMatch = PWD.STR.match(/^[a-zA-Z]+$/);
			onlyLetters = onlyLettersMatch ? (onlyLettersMatch[0].length === PWD.LEN) : false;

			// speed up script. If onlyLetters then onlyNumeric is false
			if(!onlyLetters){
				var onlyNumericMatch = PWD.STR.match(/^[0-9]+$/);
				onlyNumeric = onlyNumericMatch ? (onlyNumericMatch[0].length === PWD.LEN) : false;
			}

			// speed up script. If onlyLetters OR onlyNumeric then onlySymbols is false
			if(!onlyLetters || !onlyNumericMatch){
				var onlySymbolsMatch = PWD.STR.match(/^[^a-zA-Z0-9]+$/);
				onlySymbols = onlySymbolsMatch ? (onlySymbolsMatch[0].length === PWD.LEN) : false;
			}
		};

		this.determineThings = function(){
			checkOnlys();
			this.determineCharacters();
			this.determineSequences();
			this.repeatedAndMirroredSequences();
			this.calculateEntropy();
			this.determineKeyboardPatterns();
		};

		this.determineCharacters = function(){

			// reset counters
			pwdchk.merit.lowercaseCount.count = 0;
			pwdchk.merit.uppercaseCount.count = 0;
			pwdchk.merit.numericCount.count   = 0;
			pwdchk.merit.symbolCount.count    = 0;
			pwdchk.merit.middleNumericCount.count = 0;
			pwdchk.merit.middleSymbolCount.count  = 0;

			pwdchk.infraction.consecutiveLowercase.count = 0;
			pwdchk.infraction.consecutiveUppercase.count = 0;
			pwdchk.infraction.consecutiveNumbers.count   = 0;
			pwdchk.infraction.consecutiveSymbols.count   = 0;

			var tempAlphaLC = -1,
				tempAlphaUC = -1,
				tempNumeric = -1,
				tempSymbol  = -1,
				numericStartEndCheck = false,
				symbolsStartEndCheck = false;

			/**
			 * Character counter
			 *
			 * @param {Number} iterator Loop counter
			 * @param {Number} tempValue Value of temp variable
			 * @param {Object} countsObj Object who's count will be adjusted
			 * @param {Object} consecutiveObj Object who's consecutive count will be adjusted
			 * @returns {Number} tempValue to keep the loop going
			 */
			var loopyCharCounter = function(iterator, tempValue, countsObj, consecutiveObj){
				if (tempValue !== -1) {
					if ((tempValue + 1) === iterator) consecutiveObj.count++;
				}
				tempValue = iterator;
				countsObj.count++;

				return tempValue;
			};

			/**
			 * Middle character counter
			 *
			 * @param {Number} iterator Loop counter
			 * @param {Boolean} onetimeCheck Flag to insure a certain check is run only once
			 * @param {Object} countsObj Object who's count will be adjusted, and regex used
			 * @returns {Boolean} onetimeCheck to keep the loop going
			 */
			var loopyMiddleCounter = function(iterator, onetimeCheck, countsObj){

				// if in middle of the string
				if(iterator !== 0 && iterator !== (PWD.LEN-1)){
					if(PWD.STR.match(countsObj.regex)) {
						countsObj.count++;
					}
				}
				// only do this once in the loop
				if(!onetimeCheck && countsObj.count !== 0){
					var stuffAtStart = PWD.STR.match(countsObj.regexStart),
						stuffAtEnd   = PWD.STR.match(countsObj.regexEnd);

					// If there are numbers/symbols at the start/end of the string
					// remove their lengths from the middleCounter
					if(stuffAtStart)
						countsObj.count -= (stuffAtStart[0].length - 1);
					if(stuffAtEnd)
						countsObj.count -= (stuffAtEnd[0].length - 1);
					onetimeCheck = true;
				}
				return onetimeCheck;

			};

			// Loop through password to check for
			// Uppercase, Lowercase, Numeric, and Symbol pattern matches
			for (var a = 0; a < PWD.LEN; a++) {

				// Lowercase letters
				if (PWD.ARR[a].match(pwdchk.merit.lowercaseCount.regex)) {
					tempAlphaLC = loopyCharCounter(a, tempAlphaLC, pwdchk.merit.lowercaseCount, pwdchk.infraction.consecutiveLowercase);
				}
				// Uppercase letters
				else if (PWD.ARR[a].match(pwdchk.merit.uppercaseCount.regex)){
					tempAlphaUC = loopyCharCounter(a, tempAlphaUC, pwdchk.merit.uppercaseCount, pwdchk.infraction.consecutiveUppercase);
				}
				// Numeric
				else if (PWD.ARR[a].match(pwdchk.merit.numericCount.regex)) {
					tempNumeric = loopyCharCounter(a, tempNumeric, pwdchk.merit.numericCount, pwdchk.infraction.consecutiveNumbers);

					// If only Numeric characters are used, do not do these counts
					if(!onlyNumeric)
						numericStartEndCheck = loopyMiddleCounter(a, numericStartEndCheck, pwdchk.merit.middleNumericCount);
				}
				// Extra characters
				else if (PWD.ARR[a].match(pwdchk.merit.symbolCount.regex)) {
					tempSymbol = loopyCharCounter(a, tempSymbol, pwdchk.merit.symbolCount, pwdchk.infraction.consecutiveSymbols);

					// If only Symbol characters are used, do not do these counts
					if(!onlySymbols)
						symbolsStartEndCheck = loopyMiddleCounter(a, symbolsStartEndCheck, pwdchk.merit.middleSymbolCount);
				} else {
					console.warn('Character #'+ (a+1) + ': "'+ PWD.ARR[a] +'" is not catered for');
				}
			}

		};

		this.determineSequences = function(){
			// NOTE: this.determineCharacters() should be executed first

			// reset counters
			pwdchk.misdemeanour.sequentialLetters.count = 0;
			pwdchk.misdemeanour.sequentialNumbers.count = 0;
			pwdchk.misdemeanour.sequentialSymbols.count = 0;

			// Only continue if the password has reached the minimum length for a sequence to exist
			// Note: all sequence check lengths are the same by design.
			if(PWD.LEN >= pwdchk.misdemeanour.sequenceLengthToMatch){

				var allLowercasePassword = PWD.STR.toLowerCase();

				var sequenceFinder = function(sequenceObj){
					// Cater for rotation at the end of sequence
					var sequenceStr = sequenceObj.sequence + sequenceObj.sequence.substring(0, pwdchk.misdemeanour.sequenceLengthToMatch);

					// Determine loop counter maximum
					var	counterMax = sequenceStr.length - pwdchk.misdemeanour.sequenceLengthToMatch;

					for (var s = 0; s < counterMax; s++) {
						var forwardStr = sequenceStr.substring(s, s + pwdchk.misdemeanour.sequenceLengthToMatch),
							reverseStr = pwdchk.helpers.strReverse(forwardStr);

						if (allLowercasePassword.indexOf(forwardStr) !== -1) sequenceObj.count++;
						if (allLowercasePassword.indexOf(reverseStr) !== -1) sequenceObj.count++;
					}
				};

				// Speed up: First check if mixed characters are used
				// Else: Only go through the matching function for the character-set in use
				if(!onlyLetters && !onlyNumeric && !onlySymbols){
					if ((pwdchk.infraction.consecutiveLowercase.count !== 0 || pwdchk.infraction.consecutiveUppercase.count !== 0)
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= (pwdchk.merit.lowercaseCount.count + pwdchk.merit.uppercaseCount.count)){
						sequenceFinder(pwdchk.misdemeanour.sequentialLetters);
					}
					if (pwdchk.infraction.consecutiveNumbers.count !== 0
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= pwdchk.merit.numericCount.count){
						sequenceFinder(pwdchk.misdemeanour.sequentialNumbers);
					}
					if (pwdchk.infraction.consecutiveSymbols.count !== 0
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= pwdchk.merit.symbolCount.count){
						sequenceFinder(pwdchk.misdemeanour.sequentialSymbols);
					}
				}
				else if(onlyLetters){
					if ((pwdchk.infraction.consecutiveLowercase.count !== 0 || pwdchk.infraction.consecutiveUppercase.count !== 0)
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= (pwdchk.merit.lowercaseCount.count + pwdchk.merit.uppercaseCount.count)){
						sequenceFinder(pwdchk.misdemeanour.sequentialLetters);
					}
				}
				else if(onlyNumeric){
					if (pwdchk.infraction.consecutiveNumbers.count !== 0
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= pwdchk.merit.numericCount.count){
						sequenceFinder(pwdchk.misdemeanour.sequentialNumbers);
					}
				}
				else if(onlySymbols){
					if (pwdchk.infraction.consecutiveSymbols.count !== 0
						&& pwdchk.misdemeanour.sequenceLengthToMatch <= pwdchk.merit.symbolCount.count){
						sequenceFinder(pwdchk.misdemeanour.sequentialSymbols);
					}
				}
				else {
					console.warn('Character #' + PWD.LEN + ': "'+ (PWD.ARR[PWD.LEN-1]) +'" is not catered for');
				}
			}
		};

		this.repeatedAndMirroredSequences = function(){
			// reset counters
			pwdchk.misdemeanour.mirroredSequence.count = 0;
			pwdchk.misdemeanour.repeatedSequence.count = 0;

			if(PWD.LEN >= pwdchk.misdemeanour.sequenceLengthToMatch){
				var mirroredPatternsFound = [];

				// Determine loop counter maximum
				var	counterMax = PWD.LEN - pwdchk.misdemeanour.sequenceLengthToMatch;

				for (var s = 0; s <= counterMax; s++) {
					var searchFrom = s + pwdchk.misdemeanour.sequenceLengthToMatch,
						forwardStr = PWD.STR.substring(s, searchFrom),
						reverseStr = pwdchk.helpers.strReverse(forwardStr);

					// repeated sequence found
					if (PWD.STR.indexOf(forwardStr, searchFrom) !== -1) {
						pwdchk.misdemeanour.repeatedSequence.count++;
					}

					// Found it already, just continue past
					if (mirroredPatternsFound[forwardStr] !== undefined || mirroredPatternsFound[reverseStr] !== undefined)
						continue;

					// mirrored sequence found
					if (PWD.STR.indexOf(reverseStr, searchFrom) !== -1){
						mirroredPatternsFound[forwardStr] = forwardStr;
						mirroredPatternsFound[reverseStr] = reverseStr;
						pwdchk.misdemeanour.mirroredSequence.count++;
					}

				}
			}
		};

		this.determineKeyboardPatterns = function(){
			// reset counters
			pwdchk.felony.keyboardPatterns.count = 0;

			// Only continue if the password has reached the minimum length for a sequence to exist
			// Note: all sequence check lengths are the same by design.
			if(PWD.LEN >= pwdchk.misdemeanour.sequenceLengthToMatch){

				var allLowercasePassword = PWD.STR.toLowerCase(),
					sequenceStr = pwdchk.felony.keyboardPatterns.sequence;

				// Determine loop counter maximum
				var	counterMax = sequenceStr.length - pwdchk.misdemeanour.sequenceLengthToMatch + 1;

				for (var s = 0; s < counterMax; s++) {
					var forwardStr = sequenceStr.substring(s, s + pwdchk.misdemeanour.sequenceLengthToMatch),
						reverseStr = pwdchk.helpers.strReverse(forwardStr);

					if (allLowercasePassword.indexOf(forwardStr) !== -1) pwdchk.felony.keyboardPatterns.count++;
					if (allLowercasePassword.indexOf(reverseStr) !== -1) pwdchk.felony.keyboardPatterns.count++;
				}

			}
		};

		/**
		 * @author Matthijs van Henten (https://github.com/mvhenten)
		 * @source https://github.com/mvhenten/string-entropy/blob/master/index.js
		 * @licence MIT License Copyright (c) 2014 (https://github.com/mvhenten/string-entropy/blob/master/LICENSE)
		 *
		 * Modified to use other parts of this application
		 * @alias pwdchk.looper.calculateEntropy
		 */
		this.calculateEntropy = function() {
			/**
			 * Calculate the size of the alphabet.
			 *
			 *   This is a mostly back-of-the hand calculation of the alphabet.
			 *   We group the a-z, A-Z and 0-9 together with the leftovers of the keys on an US keyboard.
			 *   Characters outside ascii add one more to the alphabet.
			 *   Meaning that the alphabet size of the word: "ümlout" will yield 27 characters.
			 *   There is no scientific reasoning behind this, besides to err on the safe side.
			 */
			var i, p, c,
				alphabetSize = 0,
				collection = {
					unicode     : 0,
					unicodeAlpha: 0,
					alpha_lc    : pwdchk.merit.lowercaseCount.count !== 0 ? pwdchk.misdemeanour.sequentialLetters.sequence.length : 0,
					alpha_uc    : pwdchk.merit.uppercaseCount.count !== 0 ? pwdchk.misdemeanour.sequentialLetters.sequence.length : 0,
					digits      : pwdchk.merit.numericCount.count !== 0 ? pwdchk.misdemeanour.sequentialNumbers.sequence.length : 0,
					punctuation : pwdchk.merit.symbolCount.count !== 0 ? pwdchk.misdemeanour.sequentialSymbols.sequence.length : 0
				};
			for (i = 0; i < PWD.LEN; i++) {
				c = PWD.STR[i];

				// we only need to look at each character once
				if (PWD.STR.indexOf(c) !== i) continue;
				// I can only guess the size of a non-western alphabet.
				// The choice here is to grant an additional bonus for the character itself.
				if (c.charCodeAt(0) > 127) collection.unicode += 1;
			}

			for(p in collection){
				alphabetSize += collection[p];
			}

			PWD.ENT = PWD.LEN * Math.round( Math.log(alphabetSize) / Math.log(2) );

			// Entropy based score bonus
			// @see http://reusablesec.blogspot.com/2010/10/new-paper-on-password-security-metrics.html
			// Due to the above mentioned paper entropy scoring is commented out, as it seems useless
			// PWD.TOT += Math.round((PWD.ENT / 10) * PWD.FAC);
		};


	};

	pwdchk.namespace('pwdchk.looper', new DeterminerOfThings() );

	// ------------------------------------------------------------------------------------------------

	var Helpers = function() {

		return {

			typeOfVariable : function(variable, defaultTypes){
				if (typeof defaultTypes === 'undefined') { defaultTypes = false; }

				var varType = typeof(variable);

				if(!defaultTypes){
					if(varType === 'object'){
						if(variable instanceof Array) return 'array';
						if(variable instanceof Date) return 'date';
						if(variable instanceof jQuery) return 'jquery';
						if(variable instanceof RegExp) return 'regexp';

						return 'object';
					}
					if(varType === 'number'){
						return (String(variable).indexOf('.') !== -1) ? 'float' : 'integer';
					}
				}
				return varType;
			},

			/**
			 * Find matchsticks in a matchstick factory
			 * Similar to needle-haystack but here the 'needle' is an array
			 *
			 * @param matchstickFactory
			 * @param matchsticks
			 * @returns {Array} Array of all matched elements
			 */
			matchesInMatchstickFactory : function(matchstickFactory, matchsticks){
				for (var j = 0, foundMatches = []; j < matchsticks.length; j++) {
					if( matchstickFactory.indexOf(matchsticks[j]) >= 0 )
						foundMatches.push(matchsticks[j]);
				}
				return foundMatches;
			},

			/**
			 * Filter an array returning only unique keys
			 *
			 * @param {Array} someArray
			 * @returns {Array}
			 */
			arrayUniques : function(someArray){
				var onlyUnique = function(value, index, self) {
					return self.indexOf(value) === index;
				};
				return someArray.filter(onlyUnique);
			},

			/**
			 * Reverse String
			 *
			 * @source	http://eddmann.com/posts/ten-ways-to-reverse-a-string-in-javascript/
			 * @source	http://jsperf.com/string-reverse-function-performance
			 *
			 * @note It won't work for combining characters. @see http://stackoverflow.com/a/16776621/124222
			 *
			 * @see http://stackoverflow.com/a/14438954/124222
			 * @credit TLindig (http://stackoverflow.com/users/496587/tlindig)
			 */
			strReverse : function(str) {
				for (var i = str.length - 1, o = ''; i >= 0; o += str[i--]) { }
				return o;
			},

			/**
			 * Compile a list of object properties
			 *
			 * @param {Object} parentObj
			 * @param {Object} constructorObj
			 */
			compileListOfChildren : function(parentObj, constructorObj){
				parentObj.childObjects = [];
				for(var childObj in parentObj) {
					if(childObj === 'childObjects') continue;
					if(parentObj.hasOwnProperty(childObj) && parentObj[childObj] instanceof constructorObj) {
						parentObj.childObjects.push(childObj);
					}
				}
			}

		};

	};

	pwdchk.namespace('pwdchk.helpers', new Helpers() );

	// ------------------------------------------------------------------------------------------------

	var FieldStatusCodes = function() {

		/**
		 * Primary STATUS object
		 *
		 * @type {{
		 *    STATE_0: {name: string, class: string, code: number},
		 *    STATE_1: {name: string, class: string, code: number},
		 *    STATE_2: {name: string, class: string, code: number},
		 *    STATE_3: {name: string, class: string, code: number}
		 *   }}
		 */
		var STATUS = {
			STATE_0: {
				name	: 'Fail',
				class	: 'status-fail',
				code	: 0
			},
			STATE_1: {
				name	: 'Warning',
				class	: 'status-warn',
				code	: 1
			},
			STATE_2: {
				name	: 'Pass',
				class	: 'status-pass',
				code	: 2
			},
			STATE_3: {
				name	: 'Excellent',
				class	: 'status-exel',
				code	: 3
			}
		};

		/**
		 * Number of states defined
		 *
		 * @type {Number}
		 */
		var COUNT = Object.keys(STATUS).length;

		/**
		 * Convert a state number into a valid state object name
		 *
		 * @param {Number} aNumber The state code
		 * @returns {String}
		 */
		var codeToState = function(aNumber){
			return 'STATE_' + aNumber;
		};

		return {

			/**
			 * Get all CSS class names defined
			 *
			 * @returns {Array}
			 */
			allClasses : function() {
				var classes = [];
				for(var k = 0; k < COUNT; k++){
					classes.push(STATUS[codeToState(k)]['class']);
				}
				return classes;
			},

			/**
			 * Get a states name by it's code
			 *
			 * @param {Number} aNumber The state code
			 * @returns {String}
			 */
			getNameByCode : function(aNumber) {
				return STATUS[codeToState(aNumber)]['name'];
			},

			/**
			 * Get a states CSS class by it's code
			 *
			 * @param {Number} aNumber The state code
			 * @returns {String}
			 */
			getClassByCode : function(aNumber) {
				return STATUS[codeToState(aNumber)]['class'];
			},

			/**
			 * Get a state object by it's code
			 *
			 * @param {Number} aNumber The state code
			 * @returns {Object}
			 */
			getStateByCode : function(aNumber) {
				return STATUS[codeToState(aNumber)];
			}

		}
	};

	pwdchk.namespace('pwdchk.state', new FieldStatusCodes() );

	// ------------------------------------------------------------------------------------------------

	var PasswordGrades = function() {
		/**
		 * Primary GRADE object
		 *
		 * @type {{
		 *    GRADE_A: {name: String, max: Number, min: Number},
		 *    GRADE_B: {name: String, max: Number, min: Number},
		 *    GRADE_C: {name: String, max: Number, min: Number},
		 *    GRADE_D: {name: String, max: Number, min: Number},
		 *    GRADE_E: {name: String, max: Number, min: Number}
		 * }}
		 */
		var GRADE = {
			A: {
				name: 'Very Strong', // excellent
				max : 100,
				min : 80
			},
			B: {
				name: 'Strong', // good
				max : 79,
				min : 60
			},
			C: {
				name: 'Good', // average
				max : 59,
				min : 40
			},
			D: {
				name: 'Weak', // poor
				max : 39,
				min : 20
			},
			E: {
				name: 'Very Weak', // fail
				max : 19,
				min : 0
			}
		};

		var gradeArray = ['A', 'B', 'C', 'D', 'E'];

		/**
		 * Determine the current grade
		 */
		this.determineGrade = function(){
			for(var i = 0; i < gradeArray.length; i++){
				var minimum = GRADE[gradeArray[i]]['min'],
					maximum = GRADE[gradeArray[i]]['max'];

				if(minimum <= PWD.ADJ && PWD.ADJ <= maximum){
					PWD.GRA = GRADE[gradeArray[i]]['name'];
					i = gradeArray.length; // break loop
				}
			}
		};

	};

	pwdchk.namespace('pwdchk.grade', new PasswordGrades() );

	// ------------------------------------------------------------------------------------------------

	var charSpecs = function(objectWithOptions){
		this.count   = 0;	// count of char in input string
		this.rating  = 0;	// score rating of particular field
		this.factor  = 0; 	// score rating factor
		this.status  = 0;		// status grade code of particular field
		//this.maximum  = 0;	// maximum chars allowed, before penalty comes into play
		//this.minimum  = 0;	// minimum chars to reach, before penalty becomes a bonus

		// Extend the base object
		if(objectWithOptions !== null)
			for (var keyName in objectWithOptions) {
				this[keyName] = objectWithOptions[keyName];
			}
	};
	charSpecs.prototype.tallyRating = function(){
		PWD.tallyScore(this.rating);
	};

	// ------------------------------------------------------------------------------------------------

	var TheBasicsClass = function() {

		var BasicDefaults = function(obj){
			charSpecs.call(this,obj);
			return this;
		};
		BasicDefaults.prototype = Object.create(charSpecs.prototype);

		/**
		 * Mark and score the basic password requirements
		 * @alias pwdchk.basic.requirements
		 */
		this.requirements = new BasicDefaults({
			minimum	: 6,
			factor	: 3,
			score	: function () {
				var _this = this,
					warningBreakPoint = 5;

				_this.count = 0;
				_this.count += (pwdchk.merit.characterCountNormal.status === 3)    ? 1 : 0;
				_this.count += (pwdchk.merit.characterCountRecommended.status > 1) ? 1 : 0;
				_this.count += (pwdchk.merit.lowercaseCount.status === 3)          ? 1 : 0;
				_this.count += (pwdchk.merit.uppercaseCount.status === 3)          ? 1 : 0;
				_this.count += (pwdchk.merit.numericCount.status === 3)            ? 1 : 0;
				_this.count += (pwdchk.merit.symbolCount.status === 3)             ? 1 : 0;
				_this.count += (pwdchk.merit.middleNumericCount.status > 1)        ? 1 : 0;
				_this.count += (pwdchk.merit.middleSymbolCount.status > 1)         ? 1 : 0;

				_this.count -= (pwdchk.infraction.repeatedCharacters.status > 1)   ? 0 : 1;
				_this.count -= (pwdchk.misdemeanour.sequentialLetters.status > 1)  ? 0 : 1;
				_this.count -= (pwdchk.misdemeanour.sequentialNumbers.status > 1)  ? 0 : 1;
				_this.count -= (pwdchk.misdemeanour.sequentialSymbols.status > 1)  ? 0 : 1;
				_this.count -= (pwdchk.misdemeanour.mirroredSequence.status > 1)   ? 0 : 1;
				_this.count -= (pwdchk.misdemeanour.repeatedSequence.status > 1)   ? 0 : 1;
				_this.count -= (pwdchk.felony.yearPatterns.status > 1)             ? 0 : 1;
				_this.count -= (pwdchk.felony.keyboardPatterns.status > 1)         ? 0 : 1;
				_this.count -= (pwdchk.felony.commonWords.status > 1)              ? 0 : 1;

				if(_this.count<0) _this.count = 0;

				_this.rating = _this.count * _this.factor;

				if(_this.count > _this.minimum)
					_this.status = 3;
				else if(_this.count === _this.minimum)
					_this.status = 2;
				else if(_this.count >= warningBreakPoint)
					_this.status = 1;
				else
					_this.status = 0;

				_this.tallyRating();

				// Being the last check to run:
				PWD.lastCall();

				return _this;
			}

		});

	};

	pwdchk.namespace('pwdchk.basic', new TheBasicsClass() );

	// ------------------------------------------------------------------------------------------------

	var MeritClass = function() {

		var ConstructiveDefaults = function(obj){
			this.minimum = 1;	// minimum chars to reach; before penalty becomes a bonus
			this.status  = 0;   // 'fail' status code
			charSpecs.call(this,obj);

			return this;
		};
		ConstructiveDefaults.prototype = Object.create(charSpecs.prototype);
		/**
		 * Prototyped scoring function
		 *   It calls each objects' rating function (if they have one) then it tallies the totals
		 *
		 * @returns {ConstructiveDefaults}
		 */
		ConstructiveDefaults.prototype.score = function(){
			var _this = this;

			if(_this.hasOwnProperty('rateCount'))
				_this.rateCount();

			_this.tallyRating();
			return _this;
		};

		/**
		 * Object for counting characters up to a minimum length.
		 *
		 * @alias pwdchk.merit.characterCountNormal
		 */
		this.characterCountNormal = new ConstructiveDefaults({
			minimum	: 8,
			factor	: 1,
			warningBreakPoint : 6, // this.minimum - 2
			rateCount : function () {
				var _this = this;
				_this.count = PWD.LEN;

				if(_this.count < _this.warningBreakPoint){
					_this.status = 0;
					_this.rating = (_this.count - _this.minimum) * _this.factor;
				}
				else if(_this.count < _this.minimum){ // && _this.count >= _this.warningBreakPoint
					_this.status = 1;
					_this.rating = (_this.count - _this.warningBreakPoint) * _this.factor;
				}
				else if(_this.count === _this.minimum){
					_this.status = 2;
					_this.rating = _this.warningBreakPoint;
				}
				else if(_this.count > _this.minimum){
					_this.status = 3;
					_this.rating = _this.minimum;
				}
			}
		});

		/**
		 * Object for counting characters up to a recommended length.
		 *
		 * @alias pwdchk.merit.characterCountRecommended
		 */
		this.characterCountRecommended = new ConstructiveDefaults({
			minimum	: 12,
			factor	: 1,
			warningBreakPoint : 8, // characterCountNormal.minimum
			rateCount : function () {
				var _this = this;
				_this.count = PWD.LEN;

				if(_this.count < _this.warningBreakPoint){
					_this.status = 0;
					_this.rating = (_this.count - _this.minimum) * _this.factor;
				}
				else if(_this.count < _this.minimum){ // && _this.count >= _this.warningBreakPoint
					_this.status = 1;
					_this.rating = (_this.count - _this.warningBreakPoint) * _this.factor;
				}
				else if(_this.count === _this.minimum){
					_this.status = 2;
					_this.rating = _this.warningBreakPoint;
				}
				else if(_this.count > _this.minimum){
					_this.status = 3;
					_this.rating = _this.count * _this.factor;
				}
			}
		});

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		/**
		 * Specialised rateCount function for alpha, numeric and symbol counts
		 */
		ConstructiveDefaults.prototype.alphaNumSymRateCount = function(){
			var _this = this;

			_this.rating = _this.count * _this.factor;

			if(_this.count < _this.minimum){
				var warningBreakPoint = _this.minimum - 1;
				_this.status = (_this.count >= warningBreakPoint) ? 1 : 0;
				_this.rating *= -1;
			}
			else if(_this.count === _this.minimum){
				_this.status = 2;
			}
			else if(_this.count > _this.minimum){
				_this.status = 3;
			}
		};

		/**
		 * Object for counting Lower Case characters
		 *
		 * @alias pwdchk.merit.lowercaseCount
		 */
		this.lowercaseCount = new ConstructiveDefaults({
			minimum	: 2,
			factor	: 1,
			regex	: /[a-z]/g,
			warningBreakPoint : 1, // this.minimum - 1
			rateCount : function () {
				this.alphaNumSymRateCount(); // call specialised prototyped function
			}
		});

		/**
		 * Object for counting Upper Case characters
		 *
		 * @alias pwdchk.merit.uppercaseCount
		 */
		this.uppercaseCount = new ConstructiveDefaults({
			minimum	: 2,
			factor	: 2,
			regex	: /[A-Z]/g,
			warningBreakPoint : 1, // this.minimum - 1
			rateCount : function () {
				this.alphaNumSymRateCount(); // call specialised prototyped function
			}
		});

		/**
		 * Object for counting Numeric characters
		 *
		 * @alias pwdchk.merit.numericCount
		 */
		this.numericCount = new ConstructiveDefaults({
			minimum	: 2,
			factor	: 2,
			regex	: /[0-9]/g,
			warningBreakPoint : 1, // this.minimum - 1
			rateCount : function () {
				this.alphaNumSymRateCount(); // call specialised prototyped function
			}
		});

		/**
		 * Object for counting Symbol characters
		 *
		 * @alias pwdchk.merit.symbolCount
		 */
		this.symbolCount = new ConstructiveDefaults({
			minimum	: 2,
			factor	: 3,
			regex	: /[^0-9a-zA-Z]/g,
			warningBreakPoint : 1, // this.minimum - 1
			rateCount : function () {
				this.alphaNumSymRateCount(); // call specialised prototyped function
			}
		});

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		/**
		 * Specialised rateCount function for middle counts
		 *
		 * @returns {ConstructiveDefaults}
		 */
		ConstructiveDefaults.prototype.middelRateCount = function(){
			var _this = this;
			_this.rating = (_this.count - _this.minimum) * _this.factor;

			if(_this.count < _this.minimum){
				_this.status = 0;
			}
			else if(_this.count === _this.minimum){
				_this.status = 2;
				_this.rating = 0;
			}
			else if(_this.count > _this.minimum){
				_this.status = 3;
			}
		};

		/**
		 * Counting middle Numeric characters
		 *
		 * @alias pwdchk.merit.middleNumericCount
		 */
		this.middleNumericCount = new ConstructiveDefaults({
			minimum	: 1,
			factor	: 4,
			regex	: /^.*[^0-9].*[0-9]+.*[^0-9].*$/,
			regexStart	: /^[0-9]+/,
			regexEnd	: /[0-9]+$/,
			warningBreakPoint : 0, // not used
			rateCount : function () {
				this.middelRateCount(); // call specialised prototyped function
			}
		});

		/**
		 * Counting middle Symbol characters
		 *
		 * @alias pwdchk.merit.middleSymbolCount
		 */
		this.middleSymbolCount = new ConstructiveDefaults({
			minimum	: 1,
			factor	: 4,
			regex	: /^.*[0-9a-zA-Z].*[^0-9a-zA-Z]+.*[0-9a-zA-Z].*$/,
			regexStart	: /^[^0-9a-zA-Z]+/,
			regexEnd	: /[^0-9a-zA-Z]+$/,
			warningBreakPoint : 0, // not used
			rateCount : function () {
				this.middelRateCount(); // call specialised prototyped function
			}
		});

		pwdchk.helpers.compileListOfChildren(this, ConstructiveDefaults);

	};

	pwdchk.namespace('pwdchk.merit', new MeritClass() );

	// ------------------------------------------------------------------------------------------------

	var InfractionClass = function() {

		var MinorOffence = function(obj){
			this.maximum = 2;	// maximum chars allowed; before bonus becomes a penalty
			this.status  = 3;   // 'pass' status code
			charSpecs.call(this,obj);
			return this;
		};
		MinorOffence.prototype = Object.create(charSpecs.prototype);
		MinorOffence.prototype.score = function(){
			var _this = this;

			if(_this.hasOwnProperty('calc'))
				_this.calc();

			if(_this.count < _this.maximum){
				_this.status = 2;
				_this.rating = 0;
			} else if(_this.count === _this.maximum){
				_this.status = 1;
				_this.rating = 0;
			} else {
				_this.status = 0;
				_this.rating = _this.count * _this.factor;
			}

			_this.tallyRating();
			return _this;
		};

		this.repeatedCharacters = new MinorOffence({
			maximum	: 1,
			factor	: -2,
			calc	: function () {
				var uniqueCharacters = pwdchk.helpers.arrayUniques(PWD.ARR);
				this.count = PWD.LEN - uniqueCharacters.length;
			}
		});

		this.consecutiveLowercase = new MinorOffence({
			factor	: -1
		});

		this.consecutiveUppercase = new MinorOffence({
			factor	: -1
		});

		this.consecutiveNumbers = new MinorOffence({
			factor	: -3
		});

		this.consecutiveSymbols = new MinorOffence({
			factor	: -3
		});

		pwdchk.helpers.compileListOfChildren(this, MinorOffence);

	};

	pwdchk.namespace('pwdchk.infraction', new InfractionClass() );

	// ------------------------------------------------------------------------------------------------

	var MisdemeanourClass = function() {

		var IntermediateOffence = function(obj){
			this.maximum = 0;	// maximum chars allowed; before bonus becomes a penalty
			this.status  = 3;   // 'pass' status code
			charSpecs.call(this,obj);

			return this;
		};
		IntermediateOffence.prototype = Object.create(charSpecs.prototype);
		IntermediateOffence.prototype.score = function(){
			var _this = this;

			if(_this.count === 0){
				_this.status = 2;
				_this.rating = 0;
			}
			else {
				_this.status = 0;
				_this.rating = _this.count * _this.factor;
			}

			_this.tallyRating();
			return _this;
		};

		/**
		 * All sequences have the same number of character lengths to match
		 * (it makes the calculations easier)
		 *
		 * @type {Number}
		 */
		this.sequenceLengthToMatch = 3;

		/**
		 * @alias pwdchk.misdemeanour.sequentialLetters
		 */
		this.sequentialLetters = new IntermediateOffence({
			factor	: -4,
			sequence: 'abcdefghijklmnopqrstuvwxyz'
		});

		/**
		 * @alias pwdchk.misdemeanour.sequentialNumbers
		 */
		this.sequentialNumbers = new IntermediateOffence({
			factor	: -5,
			sequence: '0123456789'
		});

		this.sequentialSymbols = new IntermediateOffence({
			factor	: -5,
			sequence: '~!@#$%^&*()_+{}\\:"<>?-=[]|;\',./'
		});

		this.mirroredSequence = new IntermediateOffence({
			factor	: -6
		});

		this.repeatedSequence = new IntermediateOffence({
			factor	: -6
		});

		pwdchk.helpers.compileListOfChildren(this, IntermediateOffence);

	};

	pwdchk.namespace('pwdchk.misdemeanour', new MisdemeanourClass() );

	// ------------------------------------------------------------------------------------------------

	var FelonyClass = function() {

		var SeriousOffences = function(obj){
			this.status  = 3;   // 'pass' status code
			charSpecs.call(this, obj);
			this.maximum = 0;
			return this;
		};
		SeriousOffences.prototype = Object.create(charSpecs.prototype);
		SeriousOffences.prototype.score = function(){
			var _this = this;

			if(_this.hasOwnProperty('calc'))
				_this.calc();

			if(_this.count === 0){
				_this.status = 2;
				_this.rating = 0;
			}
			else {
				_this.status = 0;
				_this.rating = _this.count * _this.factor;
			}

			_this.tallyRating();
			return _this;
		};

		this.keyboardPatterns = new SeriousOffences({
			factor	: -10,
			// in order:
			// US-EN horizontal qwertyuiopasdfghjklzxcvbnm
			// US-EN vertical   1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-[=]
			// DE horizontal    qwertzuiopasdfghjklyxcvbnm!\"§$%&/()=
			// DE vertical      1qay2wsx3edc4rfv5tgb6zhn7ujm8ik,9ol.0pö-üä+#"
			sequence: 'qwertyuiopasdfghjklzxcvbnm' +
			'1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-[=]' +
			'rtzuiklyxc!"§$%&/()=' +
			'1qay2wb6zhn.0pö-üä+#'
		});

		this.yearPatterns = new SeriousOffences({
			factor	: -20,
			regex	: /1[89][0-9][0-9]|2[0-2][0-9][0-9]/g,	// matches between 1800-2299
			calc	: function () {
				var _this = this;

				// reset counter
				_this.count = 0;

				// if password has reached a minimum character length
				if (PWD.LEN >= 4) {
					var matchedPattern = PWD.STR.match(_this.regex);
					if(matchedPattern) _this.count = matchedPattern.length;
				}
			}

		});

		var commonWordsStr = "911|314159|27182\
			a#shole|access|action|albert|alex|amanda|amateur|andre|angel|animal|anthony|apollo|apple|arsenal|\
			arthur|ashley|august|austin|baby|bailey|ball|banana|barney|batman|beach|bear|beaver|beavis|beer|bill|birdie|bitch|\
			bite|bl#w|black|blazer|blonde|blow|blue|bond007|bonnie|boob|booger|boom|booty|boston|boy|brand|braves|brazil|brian|\
			bronco|bubba|buddy|bust|butt|c#ck|c#m|c#nt|calvin|camaro|canada|captain|carlos|carter|casper|charl|cheese|chelsea|\
			chester|chevy|chicago|chicken|chris|cocacola|coffee|college|comp|cookie|cool|cooper|corvette|cow|cream|crystal|daddy|\
			dakota|dallas|daniel|dave|david|debbie|dennis|diablo|diamond|dick|dirty|doctor|dog|dolphin|donald|dragon|dreams|driver|\
			eagle|edward|einstein|enjoy|enter|eric|erotic|ever|extreme|f#ck|falcon|fender|ferrari|fire|fish|florida|flower|flyers|\
			ford|forever|frank|fred|freedom|gandalf|gateway|gators|gemini|george|giants|ginger|girl|gold|golf|gordon|great|green|\
			gregory|guitar|gunner|hammer|hannah|happy|hardcore|harley|heather|hell|helpme|hentai|hockey|hooters|horn|house|hunt|\
			iceman|internet|jack|jaguar|jake|james|japan|jasmine|jason|jasper|jenn|jeremy|jessica|john|jordan|joseph|joshua|juice|\
			junior|justin|kelly|kevin|killer|king|kitty|knight|ladies|lakers|lauren|leather|legend|letmein|little|london|love|lucky|\
			maddog|madison|maggie|magic|magnum|marine|mark|marlboro|martin|marvin|master|matrix|matt|maverick|max|melissa|member|\
			merc|merlin|mich|mick|midnight|mike|miller|mine|mistress|money|monica|monkey|monster|morgan|mother|mountain|movie|muff|\
			murphy|music|mustang|naked|nascar|nathan|naught|newyork|nicholas|nicole|nipple|oliver|orange|p#ss|pa#s|pa#sword|packers|\
			pant|paris|parker|patrick|paul|peach|peanut|penis|pepper|peter|phantom|phoenix|player|please|pookie|porn|porsche|power|\
			prince|private|purple|rabbit|rachel|racing|raid|rainbow|ranger|rebecca|red|richard|rob|rock|rosebud|run|rush|russia|\
			sam|sandra|saturn|scooby|scoot|scorpio|scott|secret|sex|shadow|shannon|shaved|shit|sierra|silver|skip|slayer|slut|\
			smith|smoke|snoop|soccer|sophie|spank|spark|spider|squirt|srinivas|star|steelers|steve|sticky|stupid|success|suckit|\
			summer|sunshine|super|surfer|swim|sydney|taylor|teens|tennis|teresa|test|the|thomas|thunder|thx|tiffany|tiger|tigger|\
			time|tits|tom|topgun|toyota|travis|trouble|trust|tucker|turtle|united|vagina|victor|victoria|video|viking|viper|voodoo|\
			voyager|walter|want|warrior|welcome|what|white|will|wilson|winner|winston|winter|wizard|wolf|women|xavier|yamaha|yank|yellow|young";

		this.commonWords = new SeriousOffences({
			factor	: -20,
			regex: new RegExp(commonWordsStr,'ig'),
			calc	: function () {
				var _this = this;

				// reset counter
				_this.count = 0;

				// if password has reached a minimum character length
				if (PWD.LEN >= 6) {
					var matchedWords = PWD.STR.match(_this.regex);
					if(matchedWords) _this.count = matchedWords.length;
				}
			}
		});

		pwdchk.helpers.compileListOfChildren(this, SeriousOffences);

	};

	pwdchk.namespace('pwdchk.felony', new FelonyClass() );

})();

/* ------------------------------------------------------------------------------------------------ */