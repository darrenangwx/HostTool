$(function() {

    Morris.Area({
        element: 'morris-area-chart',
        data: [{
            period: '11-02-17',
            HoneyPy: 6497,
			Dionaea: 8760,
			Cowrie: 1232
        },
		{
            period: '12-02-17',
            HoneyPy: 5687,
			Dionaea: 1840,
			Cowrie: 4852
        },
		{
            period: '13-02-17',
            HoneyPy: 9786,
			Dionaea: 6955,
			Cowrie: 7377
        },
		{
            period: '14-02-17',
            HoneyPy: 6897,
			Dionaea: 4626,
			Cowrie: 8741
        }],
        xkey: 'period',
        ykeys: ['HoneyPy','Dionaea','Cowrie'],
        labels: ['HoneyPy','Dionaea','Cowrie'],
		parseTime:false,
        pointSize: 2,
        hideHover: 'auto',
        resize: true
    });

    Morris.Donut({
        element: 'morris-donut-chart',
        data: [{
            label: "Download Sales",
            value: 12
        }, {
            label: "In-Store Sales",
            value: 30
        }, {
            label: "Mail-Order Sales",
            value: 20
        }],
        resize: true
    });

    Morris.Bar({
        element: 'morris-bar-chart',
        data: [{
            y: '2006',
            a: 100,
            b: 90
        }, {
            y: '2007',
            a: 75,
            b: 65
        }, {
            y: '2008',
            a: 50,
            b: 40
        }, {
            y: '2009',
            a: 75,
            b: 65
        }, {
            y: '2010',
            a: 50,
            b: 40
        }, {
            y: '2011',
            a: 75,
            b: 65
        }, {
            y: '2012',
            a: 100,
            b: 90
        }],
        xkey: 'y',
        ykeys: ['a', 'b'],
        labels: ['Series A', 'Series B'],
        hideHover: 'auto',
        resize: true
    });
    
});
