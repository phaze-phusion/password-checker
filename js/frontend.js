var PasswordCalculator = (function ($) {

	var $rows_of = function(ids_arr){
			var $rows = $('#'+ids_arr[0]);
			for(var i = 1, arr_length = ids_arr.length; i < arr_length; i++){
				$rows = $rows.add('#'+ids_arr[i]);
			}
			return $rows;
		},
		writer = function(variable){
			if(variable === 0) return '-';
			return variable;
		};

	var $row_basic = $('#requirements'),
		$rows_merit = $rows_of(pwdchk.merit.childObjects),
		$rows_infraction = $rows_of(pwdchk.infraction.childObjects),
		$rows_misdemeanour = $rows_of(pwdchk.misdemeanour.childObjects),
		$rows_felony = $rows_of(pwdchk.felony.childObjects);

	var bootstrap_colors = ['text-danger', 'text-warning', 'text-success', 'text-primary'],
		bootstrap_colors_str = bootstrap_colors.join(' '),
		icon_classes = ['fa-times', 'fa-warning', 'fa-check', 'fa-plus'],
		icon_classes_str = icon_classes.join(' '),
		status_classes_str = pwdchk.state.allClasses().join(' ');

	// --------------------------------------------------

	var setCommonProps = function(objParent, trElement){
		pwdchk[objParent][trElement.id]['count'] = 0;
		$('.count',trElement).text('-');

		pwdchk[objParent][trElement.id]['rating'] = 0;
		$('.rating',trElement).text('-');

		$('.factor',trElement).text(writer(pwdchk[objParent][trElement.id]['factor']));
	};

	var constructive_status = {
		name : pwdchk.state.getNameByCode(0),
		class : pwdchk.state.getClassByCode(0),
		icon : icon_classes[0],
		color : bootstrap_colors[0]
	};

	var setCommonConstructiveProps = function(objParent, trElement){
		var $tr = $(trElement);
		setCommonProps(objParent, trElement);

		$tr.removeClass(status_classes_str)
			.addClass(constructive_status.class)
			.addClass('row-'+objParent)
			.children('.status')
				.removeClass(bootstrap_colors_str)
				.addClass(constructive_status.color)
				.children('.fa')
					.removeClass(icon_classes_str)
					.addClass(constructive_status.icon)
					.attr('title', constructive_status.name);
		$('.minimum', $tr).text(pwdchk[objParent][trElement.id]['minimum']);
	};

	var destructive_status = {
		name : pwdchk.state.getNameByCode(2),
		class : pwdchk.state.getClassByCode(2),
		icon : icon_classes[2],
		color : bootstrap_colors[2]
	};

	var setCommonDestructiveProps = function(objParent, trElement){
		var $tr = $(trElement);
		setCommonProps(objParent, trElement);

		$tr.removeClass(status_classes_str)
			.addClass(destructive_status.class)
			.addClass('row-'+objParent)
			.children('.status')
				.removeClass(bootstrap_colors_str)
				.addClass(destructive_status.color)
				.children('.fa')
					.removeClass(icon_classes_str)
					.addClass(destructive_status.icon)
					.attr('title', destructive_status.name);
		$('.maximum', $tr).text(pwdchk[objParent][trElement.id]['maximum']);
	};

	// --------------------------------------------------

	return {

		rowAdjuster : function(objParent, idString){
			var obj = pwdchk[objParent][idString];

			//if(typeof obj.calc !== 'function')
			//	console.warn(idString,obj);
			obj = obj.score();

			$('#'+idString)
				.removeClass(status_classes_str)
				.addClass(pwdchk.state.getClassByCode(obj.status))
				.children('.status')
					.removeClass(bootstrap_colors_str)
					.addClass(bootstrap_colors[obj.status])
					.children('.fa')
						.removeClass(icon_classes_str)
						.addClass(icon_classes[obj.status])
						.attr('title', pwdchk.state.getNameByCode(obj.status));

			$('#'+idString+'>.count').text(writer(obj.count));
			$('#'+idString+'>.rating').text(writer(obj.rating));
		},

		resetFrontend : function() {

			// CONSTRUCTIVE --------------------------------------------------------------

			// constructive rows: requirements
			$row_basic.each(function(i,tr){
				setCommonConstructiveProps('basic', tr);
			});

			// constructive rows: merit
			$rows_merit.each(function(i,tr){
				setCommonConstructiveProps('merit', tr);
			});

			// DESTRUCTIVE --------------------------------------------------------------

			// destructive rows: infraction
			$rows_infraction.each(function(i,tr){
				setCommonDestructiveProps('infraction',tr);
			});

			// destructive rows: misdemeanour
			$rows_misdemeanour.each(function(i,tr){
				setCommonDestructiveProps('misdemeanour',tr);
			});

			// destructive rows: felony
			$rows_felony.each(function(i,tr){
				setCommonDestructiveProps('felony',tr);
			});

			// SCORE --------------------------------------------------------------

			$('#score-graphic').css('left','0');
			$('#score-percentage').text('0%');
			$('#score-total').text(PWD.TOT);
			PWD.ENT = 0;
			$('#entropy-bits').add('#entropy-exponent').text(PWD.ENT);
			$('#complexity').text('');

			if($('#passwordMasked').hasClass('hidden'))
				$('#passwordTxt').trigger('focus');
			else
				$('#passwordPwd').trigger('focus');
		},

		adjustFrontend : function(){
			var _this = this;

			$.each(pwdchk.merit.childObjects, function(i,trId){
				_this.rowAdjuster('merit', trId);
			});

			$.each(pwdchk.infraction.childObjects, function(i,trId){
				_this.rowAdjuster('infraction', trId);
			});

			$.each(pwdchk.misdemeanour.childObjects, function(i,trId){
				_this.rowAdjuster('misdemeanour', trId);
			});

			$.each(pwdchk.felony.childObjects, function(i,trId){
				_this.rowAdjuster('felony', trId);
			});

			_this.rowAdjuster('basic', 'requirements');

			// adjust graphic left position
			// range between 0% and -900%
			$('#score-graphic').css('left', (PWD.ADJ * -9) + '%');
			$('#score-percentage').text(PWD.ADJ + '%');
			$('#score-total').text(PWD.TOT);

			$('#entropy-bits').add('#entropy-exponent').text(PWD.ENT);
			$('#complexity').text(PWD.GRA);


		}

	};

}(window.$));


(function ($) {

	var $pass_form = $('#password-checker');

	$('[data-toggle="popover"]').popover();

	// Show password characters
	$('#passwordShow').on('click touchend',function(event){
		event.stopPropagation();
		event.preventDefault();
		$('#passwordTxt').val( $('#passwordPwd').val() );
		$('#passwordMasked').add('#passwordMaskedLabel').addClass('hidden');
		$('#passwordVisible').add('#passwordVisibleLabel').removeClass('hidden');
	});
	// Hide password characters
	$('#passwordHide').on('click touchend',function(event){
		event.stopPropagation();
		event.preventDefault();
		$('#passwordPwd').val( $('#passwordTxt').val() );
		$('#passwordVisible').add('#passwordVisibleLabel').addClass('hidden');
		$('#passwordMasked').add('#passwordMaskedLabel').removeClass('hidden');
	});
	$('.try-me').on('click touchend',function(event){
		event.stopPropagation();
		event.preventDefault();
		var valueToCopy = $(event.target).text();
		$('#passwordPwd')
			.add('#passwordTxt')
			.val(valueToCopy);
		PWD.setPassword(valueToCopy, false);
		PasswordCalculator.adjustFrontend();
	});

	$('#passwordPwd')
		.add('#passwordTxt')
		.on('keyup',function(event){
			var ignoreKeyCode = function(keyCodeToTest) {
				var ignoreArr = [
					13,		// enter
					16,		// shift
					17,		// ctrl
					18		// alt
				];
				for (var l = ignoreArr.length; l >=0; l--) {
					if (ignoreArr[l] == keyCodeToTest) return true;
				}
				return false;
			};

			if(!ignoreKeyCode(event.keyCode)) {
				var password_string = event.target.value,
					previous_pass = $pass_form.data('prev');

				if(password_string !== '') {
					if(password_string !== previous_pass) {
						PWD.setPassword(password_string, false);
						PasswordCalculator.adjustFrontend();
						$pass_form.data('prev', password_string);
					}
				} else {
					PWD.setPassword('', true);
					PasswordCalculator.resetFrontend();
				}
			}
		});

	PasswordCalculator.resetFrontend();

})(jQuery);