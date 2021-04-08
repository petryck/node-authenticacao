(function($) {

    "use strict";


	//---------------------------- Sizing (svh) ----------------------------
	  function sVH() {
	    let sVHItem = document.querySelectorAll('.sVH'),
	        clientHeight = document.documentElement.clientHeight;
	    Array.prototype.forEach.call(sVHItem, function(sVHItemEl) {
	      if($(window).width() >= 1200) {
	        let scrollLeft = sVHItemEl.getBoundingClientRect(),
	        sVHBody = clientHeight - scrollLeft.top - 16 - 80;
	        if($(sVHItemEl).is(":visible")) {
	          sVHItemEl.style.height = sVHBody + 'px';
	        } else {
	          sVHItemEl.style.height = '200px';
	        }
	      } else {
	        sVHItemEl.style.height = '200px';
	      }
	    });
	  }
	  sVH();
	  window.addEventListener('resize', sVH); //resize

	  //---------------------------- Sizing (svhF) ----------------------------
	  function sVHF() {
	    let sVHItem = document.querySelectorAll('.sVHF'),
	        clientHeight = document.documentElement.clientHeight;
	    Array.prototype.forEach.call(sVHItem, function(sVHFItemEl) {
	      if($(window).width() >= 992) {
	        let scrollLeft = sVHFItemEl.getBoundingClientRect(),
	        sVHF_form_control = document.getElementById('sVHF_form').clientHeight,
	        sVHF_space_Y = 16,
	        sVHFBody = clientHeight - scrollLeft.top - sVHF_form_control - sVHF_space_Y - 16 - 80;
	        if($(sVHFItemEl).is(":visible")) {
	          sVHFItemEl.style.height = sVHFBody + 'px';
	        } else {
	          sVHFItemEl.style.height = '350px';
	        }
	      } else {
	        sVHFItemEl.style.height = '350px';
	      }
	    });
	  }
	  sVHF();
	  window.addEventListener('resize', sVHF); //resize


	  //---------------------------- Tab Scrollbar ----------------------------
	  let tab_scrollbar = document.querySelectorAll('[data-toggle="tab"]');
	  Array.prototype.forEach.call(tab_scrollbar, function(tSB) {
	    tSB.addEventListener('click', function(e) {
	      setTimeout(function(){
	        $('[data-scrollbar="tab"]').getNiceScroll().resize();
	        sVH();
	      }, 200);
	    });
	  });


	  	// tab-scrollbar
	    if ( document.querySelector('[data-scrollbar="tab"]') ) {
	      var nicescroll_dropdown = {
	          cursorcolor : 'rgba(255,255,255, .7)',
	          cursorborder : 0,
	          cursorwidth : '6px',
	          hwacceleration: true,
	          autohidemode: false,
	          iframeautoresize: true,
	          disableoutline: true,
	          smoothscroll: true,
	          enablescrollonselection: true,
	          enableobserver: true,
	          zindex : 11
	      };
	      $('[data-scrollbar="tab"]').each(function() {
	        $(this).niceScroll({
	          cursorcolor: nicescroll_dropdown.cursorcolor,
	          cursorborder: nicescroll_dropdown.cursorborder,
	          cursorwidth: nicescroll_dropdown.cursorwidth,
	          hwacceleration: nicescroll_dropdown.hwacceleration,
	          iframeautoresize: nicescroll_dropdown.iframeautoresize,
	          disableoutline: nicescroll_dropdown.disableoutline,
	          smoothscroll: nicescroll_dropdown.smoothscroll,
	          enablescrollonselection: nicescroll_dropdown.enablescrollonselection,
	          enableobserver: nicescroll_dropdown.enableobserver,
	          zindex: nicescroll_dropdown.zindex
	        });
	      });
	    }


		// chat-scrollbar
		if ( document.querySelector('[data-scrollbar="chat"]') ) {
		  let nicescroll_chat = {
		      cursorcolor : 'rgba(255,255,255, .7)',
		      cursorborder : 0,
		      cursorwidth : '6px',
		      hwacceleration: true,
		      autohidemode: false,
		      iframeautoresize: true,
		      disableoutline: true,
		      smoothscroll: true,
		      enablescrollonselection: true,
		      enableobserver: true,
		      zindex : 11
		  };
		  $('[data-scrollbar="chat"]').each(function() {
		    $(this).niceScroll({
		      cursorcolor: nicescroll_chat.cursorcolor,
		      cursorborder: nicescroll_chat.cursorborder,
		      cursorwidth: nicescroll_chat.cursorwidth,
		      hwacceleration: nicescroll_chat.hwacceleration,
		      iframeautoresize: nicescroll_chat.iframeautoresize,
		      disableoutline: nicescroll_chat.disableoutline,
		      smoothscroll: nicescroll_chat.smoothscroll,
		      enablescrollonselection: nicescroll_chat.enablescrollonselection,
		      enableobserver: nicescroll_chat.enableobserver,
		      zindex: nicescroll_chat.zindex
		    });
		  });
		}


})( jQuery );