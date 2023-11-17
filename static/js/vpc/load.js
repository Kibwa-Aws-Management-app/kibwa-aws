// Document ready function


// AJAX call to the server for inspection
$.ajax({
    url: "/vpc/inspection/",
    type: 'GET',
    dataType: 'json',
    success: function(response) {
        // 로딩이 성공적으로 완료되었을 때 실행할 코드
        if (response.results && !response.error) {
            updateInspectionPage(response.results);
        } else {
            alert(response.error || "Unknown error occurred.");
        }
    },
    error: function(xhr, status, error) {
        alert("An error occurred: " + error);
    },
    complete: function() {
        $(".loader").fadeOut("slow");
    }
});

function updateInspectionPage(results) {

    // logo png $ title
    var logoUrl = staticBaseUrl + 'img/' + results.check + '_logo.png'; // Ensure this variable is defined earlier in your code

    $('.main-content-title').html(
        '<div style="display: flex;">' +
        '<img style= "width: 50px;" class="logo" src="' + logoUrl + '" alt="' + results.check + ' logo">' +
        '<h1>' + results.check.toUpperCase() + '</h1>' +
        '</div>'
    )
    // Update the counts of passed and non-passed checks and the days since the last inspection
    $('.short-checklist').eq(0).find('div').eq(1).html(
        '<div style="font-size: 15px; font-weight: bold; color: grey; padding-top: 12px">통과된 점검</div>' +
        '<div style="font-size: 25px; font-weight: bold;">' + results.result.pass + '개</div>'
    );
    $('.short-checklist').eq(1).find('div').eq(1).html(
        '<div style="font-size: 15px; font-weight: bold; color: grey; padding-top: 12px">해결해야 할 문제점</div>' +
        '<div style="font-size: 25px; font-weight: bold;">' + results.result.non_pass + '개</div>'
    );
    $('.short-checklist').eq(2).find('div').eq(1).html(
        '<div style="font-size: 15px; font-weight: bold; color: grey; padding-top: 12px">마지막 점검일로부터</div>' +
        '<div style="font-size: 25px; font-weight: bold;">' + results.result.m_time + '일 전</div>'
    );

    // Update the table with the new inspection data
    var table_out = $('.table-container')
    table_out.css({'margin-top': '20px', 'max-height': '85%', 'overflow-y': 'auto', 'border': '1px solid #ccc;'});
    var table = $('#iam-table').addClass('security-table');
    table.find('tr:gt(0)').remove(); // Remove all rows except the header
    $.each(results.table, function (i, result) {
        var row = $('<tr/>')
            .css({
                'padding-top': '5px',
                'padding-bottom': '5px'
            });
        var tooltip = $('<div/>')
            .addClass('tooltip')
            .css({
            'position': 'relative',
            'display': 'inline-block'
            })
            .text(result.check_name);
        var tooltipText = $('<span/>')
            .addClass('tooltiptext')
            .css({
            'visibility': 'hidden',
            'width': '400px',
            'background-color': 'black',
            'color': '#fff',
            'text-align': 'center',
            'border-radius': '6px',
            'padding': '5px 0',
            'position': 'absolute',
            'z-index': '1',
            'bottom': '100%',
            'left': '50%',
            'margin-left': '-60px'
            })
            .text(result.caution);
        tooltip.append(tooltipText);
        row.append($('<td/>').append(tooltip));
        row.append($('<td/>').text(result.importance));
        row.append($('<td/>').text(result.date));
        var statusCell = $('<td/>').text(result.status ? 'PASS' : 'FAIL');
        statusCell.css('color', result.status ? 'green' : 'darkred');
        row.append(statusCell);
        row.append($('<td/>').text(result.info));
        table.append(row);
    });
    table.css({'max-width': 'inherit', 'border': 'transparent', 'border-collapse': 'collapse', 'width': '100%;'});

    // var title = $('.tooltoip').css({'color':'yellow', 'position': 'relative', 'display': 'inline-block'});

    var content = results.content; // Extract content from the results
    $('.container').html(content).fadeIn("slow");
}

$(document).on('mouseenter', '.tooltip', function() {
    $(this).find('.tooltiptext').css('visibility', 'visible');
}).on('mouseleave', '.tooltip', function() {
    $(this).find('.tooltiptext').css('visibility', 'hidden');
});

